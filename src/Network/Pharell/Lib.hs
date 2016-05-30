module Network.Pharell.Lib ( readPcap ) where

import qualified Data.ByteString.Char8   as C
import           Data.IORef
import           Network.Pcap
import           Network.Pharell.Packets ( parseByteString, Packet(..) )
import           Data.TCP
import           Control.Arrow

printPackets :: [(PktHdr, C.ByteString)] -> IO ()
printPackets xs = do
    let packets = map (parseByteString . snd) xs
    let tcpHeaders = map tcpHeader packets
    let seqs = map (seqNumber &&& ackNumber) tcpHeaders
    mapM_ print seqs

readPcap :: IO ()
readPcap = do
    handle <- openOffline "example.pcap"
    setFilter handle "tcp" True 0xffffffff
    readPcapFile handle >>= printPackets

readPcapFile :: PcapHandle -> IO [(PktHdr, C.ByteString)]
readPcapFile handle = do
    packetStore <- newIORef []
    _ <- dispatch handle (-1) (callback (\x -> modifyIORef packetStore (x:)))
    reverse <$> readIORef packetStore
    where callback store hdr wrd = toBS (hdr, wrd) >>= store
