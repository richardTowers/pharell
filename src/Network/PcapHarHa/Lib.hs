module Network.PcapHarHa.Lib ( readPcap ) where

import Network.Pcap

readPcap :: IO ()
readPcap = do
    handle <- openOffline "example.pcap"
    _ <- dispatch handle (-1) pcapCallback
    return ()

pcapCallback :: Callback
pcapCallback header word = putStrLn "packet"

