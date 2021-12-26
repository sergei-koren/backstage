/*
 * Copyright 2021 Spotify AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { AuthenticationError } from '@backstage/errors';
import { JsonValue } from '@backstage/types';
import express from 'express';
import { OAuth2Client, TokenPayload } from 'google-auth-library';
import { Logger } from 'winston';
import { TokenIssuer } from '../../identity/types';
import { CatalogIdentityClient } from '../../lib/catalog';
import { prepareBackstageIdentityResponse } from '../prepareBackstageIdentityResponse';
import {
  AuthProviderFactory,
  AuthProviderRouteHandlers,
  AuthResponse,
  BackstageSignInResult,
  ProfileInfo,
} from '../types';

const IAP_JWT_HEADER = 'x-goog-iap-jwt-assertion';

/**
 * The data extracted from the IAP token.
 *
 * @public
 */
export type GcpIapTokenInfo = {
  /**
   * The unique, stable identifier for the user.
   */
  sub: string;
  /**
   * User email address.
   */
  email: string;
  /**
   * Other fields.
   */
  [key: string]: JsonValue;
};

/**
 * A sign-in resolver that takes a validated and decoded GCP IAP issued token,
 * and returns profile info and a Backstage token for that user.
 *
 * @public
 */
export type GcpIapSignInResolver = (
  info: {
    iapToken: GcpIapTokenInfo;
  },
  context: {
    tokenIssuer: TokenIssuer;
    catalogIdentityClient: CatalogIdentityClient;
    logger: Logger;
  },
) => Promise<{
  /**
   * Simple profile info, to be passed down for use in the frontend.
   */
  profile: ProfileInfo;
  /**
   * The result of the authentication.
   */
  result: BackstageSignInResult;
  /**
   * Additional provider info, if desired, to be passed down for use in the frontend.
   */
  otherProviderInfo?: JsonValue;
}>;

/**
 * Options for {@link createGcpIapProvider}.
 *
 * @public
 */
export type GcpIapProviderOptions = {
  /**
   * Configures sign-in for this provider.
   */
  signIn: {
    /**
     * Maps an auth result to a Backstage identity for the user.
     */
    resolver: GcpIapSignInResolver;
  };
};

export type GcpIapProviderInfo = {
  /**
   * The validated and decoded IAP token.
   */
  iapToken: GcpIapTokenInfo;
  /**
   * Additional provider info, if returned by the sign-in resolver.
   */
  other?: JsonValue;
};

export async function parseToken(
  jwtToken: unknown,
  audience: string,
  oAuth2Client: OAuth2Client,
): Promise<GcpIapTokenInfo> {
  if (typeof jwtToken !== 'string' || !jwtToken) {
    throw new AuthenticationError(
      `Missing Google IAP header: ${IAP_JWT_HEADER}`,
    );
  }

  let payload: TokenPayload | undefined;
  try {
    const response = await oAuth2Client.getIapPublicKeys();
    const ticket = await oAuth2Client.verifySignedJwtWithCertsAsync(
      jwtToken,
      response.pubkeys,
      audience,
      ['https://cloud.google.com/iap'],
    );
    payload = ticket.getPayload();
  } catch (e) {
    throw new AuthenticationError(`Google IAP token verification failed, ${e}`);
  }

  if (!payload) {
    throw new AuthenticationError('Google IAP token had no payload');
  } else if (!payload.sub || !payload.email) {
    throw new AuthenticationError(
      'Google IAP token payload had no sub or email claim',
    );
  }

  return {
    ...payload,
    sub: payload.sub,
    email: payload.email,
  };
}

export class GcpIapProvider implements AuthProviderRouteHandlers {
  private readonly audience: string;
  private readonly signInResolver: GcpIapSignInResolver;
  private readonly tokenIssuer: TokenIssuer;
  private readonly catalogIdentityClient: CatalogIdentityClient;
  private readonly logger: Logger;

  constructor(options: {
    audience: string;
    signInResolver: GcpIapSignInResolver;
    tokenIssuer: TokenIssuer;
    catalogIdentityClient: CatalogIdentityClient;
    logger: Logger;
  }) {
    this.audience = options.audience;
    this.signInResolver = options.signInResolver;
    this.tokenIssuer = options.tokenIssuer;
    this.catalogIdentityClient = options.catalogIdentityClient;
    this.logger = options.logger;
  }

  async start() {}

  async frameHandler() {}

  async refresh(req: express.Request, res: express.Response): Promise<void> {
    const jwtToken = req.header(IAP_JWT_HEADER);
    const oAuth2Client = new OAuth2Client();
    const iapToken = await parseToken(jwtToken, this.audience, oAuth2Client);

    const context = {
      tokenIssuer: this.tokenIssuer,
      catalogIdentityClient: this.catalogIdentityClient,
      logger: this.logger,
    };

    const { profile, result, otherProviderInfo } = await this.signInResolver(
      { iapToken },
      context,
    );

    const response: AuthResponse<GcpIapProviderInfo> = {
      providerInfo: {
        iapToken,
        ...(otherProviderInfo ? { other: otherProviderInfo } : {}),
      },
      profile,
      backstageIdentity: prepareBackstageIdentityResponse(result),
    };

    res.json(response);
    res.status(200);
    res.end();
  }
}

/**
 * Creates an auth provider for Google Identity-Aware Proxy.
 *
 * @public
 */
export function createGcpIapProvider(
  options: GcpIapProviderOptions,
): AuthProviderFactory {
  return ({ config, tokenIssuer, catalogApi, logger }) => {
    const audience = config.getString('audience');
    const signInResolver = options.signIn.resolver;

    const catalogIdentityClient = new CatalogIdentityClient({
      catalogApi,
      tokenIssuer,
    });

    return new GcpIapProvider({
      audience,
      signInResolver,
      tokenIssuer,
      catalogIdentityClient,
      logger,
    });
  };
}
