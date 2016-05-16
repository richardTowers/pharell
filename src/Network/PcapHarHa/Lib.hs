module Network.PcapHarHa.Lib ( readPcap ) where

import Data.IORef
import Network.Pcap
import qualified Data.ByteString.Char8 as C

printPcap :: [(PktHdr, C.ByteString)] -> IO ()
printPcap xs = do
    let (hdr, bdy) = head xs
    print $ hdr
    C.putStrLn $ bdy

readPcap :: IO ()
readPcap = do
    handle <- openOffline "example.pcap"
    setFilter handle pcapFilter True 0xff
    packetStore <- newIORef []
    _ <- dispatch handle (-1) (pcapCallback $ storePacket packetStore)
    packets <- readIORef packetStore
    printPcap $ reverse packets

storePacket :: IORef [(PktHdr, C.ByteString)] -> (PktHdr, C.ByteString) -> IO ()
storePacket ref x = modifyIORef ref (x:)

-- Based on the examples in `man pcap-filter`.
-- Selects only IPv4 HTTP requests / responses
pcapFilter :: String
pcapFilter = "tcp and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)"

pcapCallback :: ((PktHdr, C.ByteString) -> IO ()) -> Callback
pcapCallback store header word = do
    packet <- toBS (header, word)
    store packet

