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

module Okta.Samples.App (app, waiApp) where

import qualified Control.Applicative                  as CA
import           Control.Lens                         ((^.))
import           Control.Monad
import           Control.Monad.Error.Class
import           Control.Monad.IO.Class               (liftIO)
import           Crypto.JWT
import           Data.Aeson                           (encode)
import qualified Data.ByteString.Lazy.Char8           as BS
import qualified Data.HashMap.Strict                  as Map
import           Data.Text.Lazy                       (Text)
import qualified Data.Text.Lazy                       as T
import           Data.Time.Format
import           Network.HTTP.Types
import           Network.Wai.Handler.Warp             (run)
import           Prelude                              hiding (exp)

import           Data.List
import           Data.Maybe
import qualified Network.Wai                          as WAI
import           Network.Wai.Middleware.RequestLogger
import           Network.Wai.Middleware.Static
import           Web.Scotty
import           Web.Scotty.Internal.Types
import           Crypto.JOSE.JWK

import           Okta.Samples.Sessions
import           Okta.Samples.Template
import           Okta.Samples.Token
import           Okta.Samples.Types
import           Okta.Samples.Utils

------------------------------
-- App
------------------------------

app :: AppCmdOptions -> IO()
app opt = do
  putStrLn "command options:"
  print opt
  let oc = mkOIDCConfig opt
  print oc
  wellknownC <- fetchWellKnownConfig oc
  case wellknownC of
    Left e -> print e
    Right wkc -> do
      keyResp <- fetchKeys (wkc ^. wellKnownJwksUri)
      case keyResp of 
        Left e2 -> print e2
        Right keys -> runApp opt oc keys wkc
  

mkOIDCConfig :: AppCmdOptions -> Config
mkOIDCConfig opt = Config oc (cmdPort opt)
    where oc = OIDC { _configScope = T.pack $ cmdScopes opt
                    , _issuer = mkIssuer opt
                    , _clientId = T.pack $ cmdClientId opt
                    , _clientSecret = Nothing
                    , _redirectUri = mkRedirectUri opt
                    }
mkRedirectUri :: AppCmdOptions -> Text
mkRedirectUri opt = T.pack ("http://localhost:" ++ (show $ cmdPort opt) ++ "/implicit/callback")
mkIssuer opt = case cmdIssuer opt of
  Trex -> "https://login.trexcloud.com"
  Prod -> "https://login.okta.com"

runApp :: AppCmdOptions -> Config -> [JWK] -> OIDCWellKnownConfigure -> IO ()
runApp opt c keys wkc = putStrLn ("Starting Server at http://localhost:" ++ show (c ^. port))
               >> waiApp opt c keys wkc
               >>= run (c ^. port)

waiApp :: AppCmdOptions -> Config -> [JWK] -> OIDCWellKnownConfigure -> IO WAI.Application
waiApp opt c keys wkc = do
  scottyApp $ do
    when (cmdDebug opt) (middleware logStdoutDev)
    middleware $ staticPolicy (mapAssetsDir >-> addBase "public")
    defaultHandler globalErrorHandler
    get "/" $ overviewH
    get "/login" $ loginRedirectH c wkc
    get "/logout" $ logoutH
    post "/implicit/callback" $ callbackH c keys


mapAssetsDir :: Policy
mapAssetsDir = policy removeAssetsPrefix
  where removeAssetsPrefix s = stripPrefix "assets/" s CA.<|> Just s

--------------------------------------------------
-- * Handlers
--------------------------------------------------

redirectToHomeM :: ActionM ()
redirectToHomeM = redirect "/"

errorM :: Text -> ActionM ()
errorM = throwError . ActionError

globalErrorHandler :: Text -> ActionM ()
globalErrorHandler t = status status401 >> errorTpl t

overviewH :: ActionM ()
overviewH = getCookieUserM >>= overviewTpl


loginRedirectH :: Config -> OIDCWellKnownConfigure -> ActionM ()
loginRedirectH c wkc = withCookieUserM (const redirectToHomeM) (loginToOkta c wkc)


loginToOkta :: Config -> OIDCWellKnownConfigure -> ActionM ()
loginToOkta c wkc =
  let oc = c ^. oidc
      concatParam (a, b) = T.intercalate "=" [a, b]
      queryStr = T.intercalate "&" $ map concatParam 
                                    [ ("client_id", oc ^. clientId)
                                    , ("response_type", "id_token")
                                    , ("response_mode", "form_post")
                                    , ("prompt", "login")
                                    , ("scope", oc ^. configScope)
                                    , ("redirect_uri", oc ^. redirectUri)
                                    , ("state", generatedState)
                                    , ("nonce", generatedNonce)
                                    ]
      fullurl = T.concat [ wkc ^. wellKnownAuthorizationEndpoint
                          , "?"
                          , queryStr
                          ]
  in
    redirect fullurl


logoutH :: ActionM ()
logoutH = deleteCookieUserM >> redirectToHomeM

callbackH :: Config -> [JWK] -> ActionM ()
callbackH c keys = do
  -- params from callback request query
  pas <- params
  let idTokenP = paramValue "id_token" pas
  let stateP = paramValue "state" pas
  let errorP = paramValue "error" pas
  let errorDescP = paramValue "error_description" pas

  -- validation failure hence error flow
  unless (null errorP) (errorM $ T.unwords $ errorP ++ [":"] ++ errorDescP)
  when (null idTokenP) (errorM "no id_token found from callback request")
  when (null stateP) (errorM "no state found from callback request")
  when (stateP /= [generatedState]) (errorM $
                           T.unlines $
                            ["state is not match: "] ++
                            [T.unwords $ "state parameter:": stateP] ++
                            [T.unwords $ "state generated:": [generatedState]]
                          )
  -- successful flow
  handleAuthCallback c idTokenP [generatedNonce] keys


handleAuthCallback :: Config -> [Text] -> [Text] -> [JWK] -> ActionM ()
handleAuthCallback c idTokenP nonceC keys = do
  r' <- liftIO $ fetchAuthUser c (head idTokenP) (head nonceC) keys
  case r' of
    Right userName -> setCookieUserM (BS.toStrict $ encode userName) >> redirectToHomeM
    Left e -> errorM e

generatedState :: Text
generatedState = "okta-hosted-login-state-xyz"

generatedNonce :: Text
generatedNonce = "okta-hosted-login-nonce-123"
