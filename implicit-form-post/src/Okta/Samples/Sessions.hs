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

module Okta.Samples.Sessions where

import           Control.Applicative     ((<$>))
import           Data.Aeson              (decode)
import qualified Data.Binary.Builder     as B
import qualified Data.ByteString         as BS
import qualified Data.ByteString.Lazy    as BSL
import           Data.Text.Lazy          (Text)
import qualified Data.Text.Lazy          as T
import qualified Data.Text.Lazy.Encoding as T
import           Web.Cookie
import           Web.Scotty

import           Okta.Samples.Types


renderSetCookie' :: SetCookie -> Text
renderSetCookie' = T.decodeUtf8 . B.toLazyByteString . renderSetCookie

--------------------------------------------------
-- * cookie ActionM
--------------------------------------------------

setCookieM :: BS.ByteString  -- ^ cookie name
           -> BS.ByteString  -- ^ cookie path
           -> BS.ByteString  -- ^ cookie value
           -> ActionM ()
setCookieM n p v = addHeader "Set-Cookie" (renderSetCookie' (def { setCookieName = n
                                                                 , setCookieValue = v
                                                                 , setCookiePath = Just p
                                                                 }))

deleteCookieM :: BS.ByteString  -- cookie name
              -> BS.ByteString  -- path
              -> ActionM ()
deleteCookieM n path = addHeader
                       "Set-Cookie"
                       (renderSetCookie' (def { setCookieName = n
                                              , setCookieValue = ""
                                              , setCookiePath = Just path
                                              , setCookieMaxAge = Just (-1000000000)
                                              }
                                         )
                       )

-- CookiesText is alias for [(Text, Text)]
--
getCookiesM' :: ActionM (Maybe CookiesText)
getCookiesM' =
    fmap (parseCookiesText . lazyToStrict . T.encodeUtf8) <$> header "Cookie"
    where
        lazyToStrict = BS.concat . BSL.toChunks

getCookieV :: Text -> Maybe CookiesText -> Maybe Text
getCookieV _ Nothing = Nothing
getCookieV _ (Just []) = Nothing
getCookieV key (Just ((a, b): xs))
  | a == T.toStrict key = Just (T.fromStrict b)
  | otherwise = getCookieV key (Just xs)

getCookiesM :: Text -> ActionM (Maybe Text)
getCookiesM key = fmap (getCookieV key) getCookiesM'

--------------------------------------------------
-- * User cookie ActionM
--------------------------------------------------

withCookieUserM :: (CookieUser -> ActionM ()) -> ActionM () -> ActionM ()
withCookieUserM yes no = do
  cu <- getCookieUserM
  case cu of
    Nothing -> no
    Just u  -> yes u

getCookieUserM :: ActionM (Maybe CookieUser)
getCookieUserM = maybe Nothing (decode . T.encodeUtf8) <$> getCookiesM "user"

setCookieUserM :: BS.ByteString -> ActionM ()
setCookieUserM = setCookieM "user" "/"

deleteCookieUserM :: ActionM ()
deleteCookieUserM = deleteCookieM "user" "/"
