module Network.Pharell.Lib ( readPcap ) where

import qualified Data.ByteString.Char8   as C
import           Data.IORef
import           Network.Pcap
import           Network.Pharell.Packets ( parseByteString )

printPackets :: [(PktHdr, C.ByteString)] -> IO ()
printPackets = mapM_ $ print . parseByteString . snd

readPcap :: IO ()
readPcap = do
    handle <- openOffline "example.pcap"
    setFilter handle ipv4HttpFilter True 0xff
    readPcapFile handle >>= printPackets
    where ipv4HttpFilter = "tcp and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)"

readPcapFile :: PcapHandle -> IO [(PktHdr, C.ByteString)]
readPcapFile handle = do
    packetStore <- newIORef []
    _ <- dispatch handle (-1) (callback (\x -> modifyIORef packetStore (x:)))
    reverse <$> readIORef packetStore
    where callback store hdr wrd = toBS (hdr, wrd) >>= store
