{-
/*!
 * Copyright (c) 2015-2016, Okta, Inc. and/or its affiliates. All rights reserved.
 * The Okta software accompanied by this notice is provided pursuant to the Apache License, Version 2.0 (the "License.")
 *
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the License.
d */
-}

{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings     #-}

module Okta.Samples.Token where

import           Control.Applicative        ((<$>))
import qualified Data.HashMap.Strict                  as Map
import           Control.Lens               hiding (iat)
import           Control.Monad
import           Crypto.JOSE.Compact
import           Crypto.JOSE.Error
import           Crypto.JOSE.JWK
import           Crypto.JWT
import           Data.Aeson                 (eitherDecode)
import           Data.Bifunctor
import           Data.ByteString.Lazy       (ByteString)
import qualified Data.ByteString.Lazy.Char8 as BS
import           Data.Either
import           Data.Maybe
import           Data.Monoid                ((<>))
import           Data.Text.Lazy             (Text)
import qualified Data.Text.Lazy             as TL
import qualified Data.Text.Lazy.Encoding    as TL
import           Data.Time
import           Network.HTTP.Conduit       (applyBasicAuth, urlEncodedBody)
import           Network.HTTP.Simple
import           Network.HTTP.Types.Header
import           Network.HTTP.Types.Status
import           Prelude                    hiding (exp)
import           Control.Monad.Error.Class (MonadError, throwError)

import           Okta.Samples.JWT
import           Okta.Samples.Types
import           Okta.Samples.Utils

fetchAuthUser :: Config
              -> Code
              -> Nonce
              -> [JWK]
              -> IO (Either Text IdTokenClaims)
fetchAuthUser c idTokenP nonceP keys = do
  let jwtData1 = decodeIdToken idTokenP
  jwtVerification <- case jwtData1 of
      Right jwtData -> do
        print $ jwtClaimsSet jwtData
        verifyJwtData c nonceP keys jwtData
      Left e        -> return $ Left e
  return (second toSimplifiedClaims jwtVerification)

toSimplifiedClaims :: JWT -> IdTokenClaims
toSimplifiedClaims jwt =
  let c = jwtClaimsSet jwt
      uc = c ^. unregisteredClaims
  in
    IdTokenClaims { _sampleClaimEmail = parseValue $ Map.lookup "email" uc
                  , _sampleClaimIss = fmap (TL.pack . show) (c ^. claimIss)
                  , _sampleClaimName = parseValue $ Map.lookup "name" uc
                  , _sampleClaimAud = fmap (TL.pack . show) (c ^. claimAud)
                  }


decodeIdToken :: Text -> Either Text JWT
decodeIdToken idTokenP = first (TL.pack . show) (decodeCompact (TL.encodeUtf8 idTokenP) :: Either Error JWT)


fetchKeys :: Text -> IO (Either TL.Text [JWK])
fetchKeys keyUri = do
  req <- genKeysRequest keyUri
  handleKeysResponse <$> httpLbs req

genKeysRequest :: Text -> IO Request
genKeysRequest keyUri = updateH <$> parseRequest (TL.unpack keyUri)

handleKeysResponse :: Response ByteString -> Either Text [JWK]
handleKeysResponse resp = do
  let rawBody = getResponseBody resp
  let rStatus = getResponseStatus resp
  if rStatus == status200 then
    bimap TL.pack (^. keys) $ eitherDecode rawBody
  else Left $ "error fetch keys: " <> TL.pack (show rStatus) <> TL.decodeUtf8 rawBody

fetchWellKnownConfig :: Config -> IO (Either TL.Text OIDCWellKnownConfigure)
fetchWellKnownConfig c = do
  req <- updateH <$> parseRequest (TL.unpack $ (c ^. oidc ^. issuer) <> "/.well-known/openid-configuration")
  handleWellKnownResponse <$> httpLbs req

updateH = addRequestHeader hAccept "application/json"

handleWellKnownResponse :: Response ByteString -> Either Text OIDCWellKnownConfigure
handleWellKnownResponse resp = do
  let rawBody = getResponseBody resp
  let rStatus = getResponseStatus resp
  if rStatus == status200 then
    bimap TL.pack id $ eitherDecode rawBody
  else Left $ "error fetch keys: " <> TL.pack (show rStatus) <> TL.decodeUtf8 rawBody
  