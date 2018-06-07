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

module Okta.Samples.Template where

import Data.Maybe
import           Control.Lens                         ((^.))
import           Control.Monad.IO.Class (liftIO)
import qualified Data.Text.Lazy         as TL
import           Data.Text.Lazy                       (Text)
import           Web.Scotty
import Lucid.Html5
import qualified Lucid.Base as H
import           Data.Semigroup ((<>))

import           Okta.Samples.Types

overviewTpl :: Maybe CookieUser -> ActionM ()
overviewTpl = lucidToHtml . homeH_

lucidToHtml :: H.Html () -> ActionM ()
lucidToHtml = html . H.renderText

errorTpl :: Text -> ActionM ()
errorTpl = lucidToHtml . errorH_

errorH_ :: Text -> H.Html ()
errorH_ error =
  html_ [lang_ "en"]
  (
    headH_
    <>
    body_ [id_ "samples"]
    (
      menuH_ Nothing
      <>
      div_ [class_ "ui padded grid relaxed", id_ "content"]
      (
        div_ [class_ "column eight wide"]
        (
          div_ [class_ "doc-overview"]
          (
            h2_ [class_ "error-desc"] "Error"
            <>
            p_ [class_ "error-desc"] (H.toHtml error)
          )
        )
      )
    )
  )


headH_ :: H.Html ()
headH_ = head_ $
  meta_ [charset_ "UTF-8"]
  <> title_ "Signin with Okta - Demo"
  <> link_ [href_ "/assets/css/semantic.min.css", type_ "text/css", rel_ "stylesheet"]
  <> link_ [href_ "/assets/css/samples.css", type_ "text/css", rel_ "stylesheet"]
  <> base_ [href_ "/"]

menuH_ :: Maybe CookieUser -> H.Html ()
menuH_ muser =
  div_ [class_ "ui inverted left fixed vertical menu"]
  (
    a_ [href_ "/", class_ "item"] "Home"
    <>
    div_ []
    (
      div_ [class_ "menu"]
      (
        if isJust muser then a_ [class_ "item", href_ "/logout"] "Logout" else mempty
      )
    )
  )

messageH_ :: Maybe CookieUser -> H.Html ()
messageH_ Nothing =
  section_ []
  (
    p_ "Hello!"
    <>
    form_ [method_ "get", action_ "/login"]
    (
      button_ [class_ "ui primary button", type_ "submit"] "Signin With Okta"
    )
  )
messageH_ (Just user) =
  let userName = fromMaybe "N/A userName" (user ^. sampleClaimName)
  in
    section_ []
    (
      p_ (H.toHtml $ "Welcome back, " `TL.append` userName)
      <>
      p_ "You have successfully authenticated against your Okta org, and have been redirected back to this application."
      <>
      (profileH_ user)
    )

profileH_ :: CookieUser -> H.Html ()
profileH_ user =
  h2_ [class_ "ui dividing header"] "My Profile"
  <>
  p_ "Below is the information that was decoded from IdToken."
  <>
  table_ [class_ "ui table compact collapsing"]
  (
    thead_ []
    (
      tr_
      (
        th_ "Claim"
        <>
        th_ "Value"
      )
    )
    <>
    tbody_
    (
      tr_ (td_ "name" <> td_ (fromMaybeToHtml $ user ^. sampleClaimName))
      <>
      tr_ (td_ "email" <> td_ (fromMaybeToHtml $ user ^. sampleClaimEmail))
      <>
      tr_ (td_ "aud" <> td_ (fromMaybeToHtml $ user ^. sampleClaimAud))
      <>
      tr_ (td_ "iss" <> td_ (fromMaybeToHtml $ user ^. sampleClaimIss))
    )
  )

fromMaybeToHtml a = H.toHtml $ fromMaybe "N/A" a

homeH_ :: Maybe CookieUser
         -> H.Html ()
homeH_ muser =
  html_ [lang_ "en"]
  (
    headH_
    <>
    body_ [id_ "samples"]
    (
      menuH_ muser
      <>
      div_ [class_ "ui padded grid relaxed", id_ "content"]
      (
        div_ [class_ "column eight wide"]
        (
          div_ [class_ "doc-overview"]
          (
            h2_ [class_ "ui dividing header"] "Okta Hosted Login"
          )
          <>
          messageH_ muser
        )
      )
    )
  )