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
 */
-}

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell   #-}

module Okta.Samples.Types where

import           Crypto.JOSE.JWK

import           Control.Lens     hiding (iat, (.=))
import           Prelude          hiding (exp)

import           Data.Aeson       (FromJSON, parseJSON)
import qualified Data.Aeson       as Aeson
import           Data.Aeson.TH
import           Data.Aeson.Types
import           Data.Text.Lazy   (Text)


type Code = Text
type State = Text
type Nonce = Text
type Port = Int
type Email = Text

--------------------------------------------------
-- * App server option
--------------------------------------------------
data GlobalIssuer = Trex | Prod deriving (Show, Read)

data AppCmdOptions = AppCmdOptions
  { cmdClientId :: String
  , cmdIssuer :: GlobalIssuer
  , cmdScopes :: String
  , cmdDebug :: Bool
  , cmdPort :: Int
  } deriving (Show)

--------------------------------------------------
-- * Auth
--------------------------------------------------

data OIDCWellKnownConfigure = OIDCWellKnownConfigure
    { _wellKnownIssuer :: Text
    , _wellKnownAuthorizationEndpoint :: Text
    , _wellKnownJwksUri :: Text
    -- TODO: more fields
    } deriving (Show, Eq)

makeLenses ''OIDCWellKnownConfigure
$(deriveJSON defaultOptions{fieldLabelModifier = camelTo2 '_' . drop 10} ''OIDCWellKnownConfigure)

type AccessToken = Text

data TokenResponse = TokenResponse { _accessToken :: AccessToken
                                   , _tokenType   :: String
                                   , _expiresIn   :: Int
                                   , _scope       :: String
                                   , _idToken     :: Text
                                   } deriving (Show, Eq)

newtype KeysResponse = KeysResponse { _keys :: [JWK]
                                    } deriving (Show, Eq)

data UserInfo = UserInfo
  { _userInfoSub           :: Text
  , _userInfoName          :: Text
  , _userInfoGivenName     :: Text
  , _userInfoFamilyName    :: Text
  , _userInfoEmail         :: Text
  , _userInfoEmailVerified :: Bool
  , _userInfoZoneinfo      :: Text
  } deriving (Show, Eq)

data IdTokenClaims = IdTokenClaims 
    { _sampleClaimName :: Maybe Text
    , _sampleClaimEmail :: Maybe Text
    , _sampleClaimIss :: Maybe Text
    , _sampleClaimAud :: Maybe Text
    } deriving (Show, Eq)

makeLenses ''TokenResponse
makeLenses ''KeysResponse
makeLenses ''UserInfo
makeLenses ''IdTokenClaims

--------------------------------------------------
-- * Config
--------------------------------------------------

data Config = Config { _oidc :: OIDC
                     , _port :: Port
                     } deriving (Show, Eq)

data OIDC = OIDC { _configScope  :: Text
                 , _issuer       :: Text
                 , _clientId     :: Text
                 , _clientSecret :: Maybe Text
                 , _redirectUri  :: Text
                 } deriving (Show, Eq)

makeLenses ''Config
makeLenses ''OIDC

--------------------------------------------------
-- * JSON instance
--------------------------------------------------

type CookieUser = IdTokenClaims
-- TODO: use generic approach to avoid boiplate code
--

instance FromJSON KeysResponse where
    parseJSON (Object v) = KeysResponse <$>
                           v .: "keys"
    parseJSON _          = mempty



instance FromJSON Config where
    parseJSON (Object v) = Config <$>
                           v .: "oidc" <*>
                           v .: "port"
    parseJSON _          = mempty


instance FromJSON OIDC where
    parseJSON (Object v) = OIDC <$>
                           v .: "scope" <*>
                           v .: "issuer" <*>
                           v .: "clientId" <*>
                           v .:? "clientSecret" <*>
                           v .: "redirectUri"
    parseJSON _          = mempty



instance FromJSON TokenResponse where
    parseJSON (Object v) = TokenResponse
                           <$> v .: "access_token"
                           <*> v .: "token_type"
                           <*> v .: "expires_in"
                           <*> v .: "scope"
                           <*> v .: "id_token"
    parseJSON _          = mempty

$(deriveJSON defaultOptions{fieldLabelModifier = camelTo2 '_' . drop 9} ''UserInfo)
$(deriveJSON defaultOptions{fieldLabelModifier = camelTo2 '_' . drop 12} ''IdTokenClaims)
