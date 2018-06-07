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
{-# LANGUAGE TemplateHaskell       #-}

module Okta.Samples.JWT where

import           Control.Lens              hiding (iat)
import           Control.Lens.TH           (makeClassyPrisms)
import           Control.Monad
import           Control.Monad.Error.Class (MonadError, throwError)
import           Control.Monad.Reader
import           Control.Monad.Time
import           Crypto.JOSE.Error
import           Crypto.JOSE.JWK
import           Crypto.JOSE.JWS
import           Crypto.JWT
import           Data.Either
import qualified Data.HashMap.Strict       as Map
import           Data.Maybe
import           Data.Text.Lazy            (Text)
import qualified Data.Text.Lazy            as TL
import           Data.Time
import           Network.URI               (isURI, parseURI)
import           Prelude                   hiding (exp)
import Control.Monad.Except

import           Okta.Samples.Types
import           Okta.Samples.Utils

data OktaJWTError
  = OktaJWSError JWTError
  | OktaError Error
  | JWTIatInTheFuture String
  | JWTNonceNotMatch
  | JWTNonceNotFound
  | JWTIssNotMatch
  | JWTAlgInHeaderNotMatch
  deriving (Eq, Show)

makeClassyPrisms ''OktaJWTError

instance AsError OktaJWTError where
  _Error = _OktaError

instance AsJWTError OktaJWTError where
  _JWTError = _OktaJWSError


maxClockSkew :: NominalDiffTime
maxClockSkew = 300

verifyJwtData :: Config
              -> Nonce
              -> [JWK]
              -> JWT
              -> IO (Either Text JWT)
verifyJwtData c nonceP jwks jwt@(JWT (JWTJWS (JWS _ ss)) _) = do
  let kids' = map (fmap param . (^. jwsHeaderKid) . (^. header)) ss
  let jwks' = [ k | k <- jwks, kid <- kids', (k ^. jwkKid) == kid, isJust kid ]

  if (null jwks') 
    then return (Left "verifyJwtData: No key found from /keys list")
    else do
      let jwk' = head jwks'
      let conf = jwtValidationSettings c
      result <- runExceptT (validateJWSJWT conf jwk' jwt
                        >> oktaValidateClaims nonceP jwt
                        >> oktaValidateAlg jwk' jwt
                      )
      return $ case result of
        Right _ -> Right jwt
        Left e  -> Left $ TL.pack $ show (e :: OktaJWTError)


jwtValidationSettings :: Config -> JWTValidationSettings
jwtValidationSettings c = defaultJWTValidationSettings
  & jwtValidationSettingsAllowedSkew .~ maxClockSkew
  & jwtValidationSettingsAudiencePredicate .~ audPredicate
  & jwtValidationSettingsCheckIssuedAt .~ True
  & jwtValidationSettingsIssuerPredicate .~ issPredicate c
  where audPredicate su = getString su == (Just . TL.toStrict) (c ^. oidc ^. clientId)
        issPredicate config' iss' = let uri' = TL.unpack (config' ^. oidc ^. issuer)
                                    in
                                      isURI uri' && (getURI iss' == parseURI uri')

oktaValidateClaims :: (MonadTime m, AsOktaJWTError e, MonadError e m)
                   => Nonce
                   -> JWT
                   -> m ()
oktaValidateClaims nonceP  (JWT _ claims') =
  sequence_ [ validateNonceClaim nonceP claims' ]


validateNonceClaim
  :: (AsOktaJWTError e, MonadError e m)
  => Nonce
  -> ClaimsSet
  -> m ()
validateNonceClaim nonceP (ClaimsSet _ _ _ _ _ _ _ uc) = do
  let nonce' = Map.lookup "nonce" uc
  case parseValue nonce' of
    Nothing -> throwError (review _JWTNonceNotFound ())
    Just a ->
      if a == nonceP
        then pure ()
        else throwError (review _JWTNonceNotMatch ())


oktaValidateAlg :: (AsOktaJWTError e, MonadError e m)
  => JWK
  -> JWT
  -> m ()
oktaValidateAlg k (JWT (JWTJWS (JWS _ ss)) _) = do
  let algOfJwss = map (param . (^. jwsHeaderAlg) . (^. header)) ss
  let algOfJwk = k ^. jwkAlg
  if null [alg | alg <- algOfJwss, algOfJwk == Just (JWSAlg alg)] then
    throwError (review _JWTAlgInHeaderNotMatch ())
    else pure ()
