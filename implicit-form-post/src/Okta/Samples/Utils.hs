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

module Okta.Samples.Utils where

import           Control.Lens               ((^.))
import qualified Data.Aeson                 as Aeson
import           Data.ByteString            (ByteString)
import qualified Data.ByteString.Lazy.Char8 as BS
import qualified Data.Text.Encoding         as T
import           Data.Text.Lazy             (Text)
import qualified Data.Text.Lazy             as TL
import           Web.Scotty.Internal.Types

import           Okta.Samples.Types

tlToBS :: TL.Text -> ByteString
tlToBS = T.encodeUtf8 . TL.toStrict

paramValue :: Text -> [Param] -> [Text]
paramValue key = fmap snd . filter (hasParam key)

hasParam :: Text -> Param -> Bool
hasParam t = (== t) . fst

parseValue :: Aeson.FromJSON a => Maybe Aeson.Value -> Maybe a
parseValue Nothing = Nothing
parseValue (Just a) = case Aeson.fromJSON a of
  Aeson.Error _   -> Nothing
  Aeson.Success b -> Just b
