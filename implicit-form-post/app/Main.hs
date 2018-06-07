{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE ApplicativeDo              #-}

module Main where

import           GHC.IO.Handle
import           GHC.IO.Handle.FD
import           System.Environment
import           Control.Monad
import           Control.Monad.IO.Class
import           Data.Maybe
import           Data.Semigroup         ((<>))
import           Data.Text              (Text)
import qualified Data.Text              as T
import           Options.Applicative

import           Okta.Samples.App   (app)
import           Okta.Samples.Types


appCmdOptions :: Parser AppCmdOptions
appCmdOptions = do
  
  cmdClientId <- strOption
    ( long "OIDC client ID"
    <> short 'c'
    <> help "client id" )
  cmdIssuer <- option auto
    ( long "issuer"
    <> short 'i'
    <> help "issuer, [ Trex | Prod ]" )
  cmdScopes <- strOption
    ( long "scopes"
    <> short 's'
    <> value "openid profile email"
    <> help "scopes; default is openid profile email" )
  cmdPort <- option auto
    ( long "port"
    <> short 'p'
    <> value 54321
    <> help "port; default 54321" )
  cmdDebug <- switch
    ( long "verbose"
    <> short 'v'
    <> help "verbose" )
  pure AppCmdOptions  {..}

main :: IO ()
main = execParser opts >>= app
  where
    opts = info (appCmdOptions <**> helper)
           ( fullDesc
             <> progDesc "Signin With Okta - implict flow with form-post"
             <> header "Welcome to Okta OIDC Sample"
           )
