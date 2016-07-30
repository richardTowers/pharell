module Network.Pharrell.Lib ( readPcap ) where

import           Control.Arrow           ((&&&))
import qualified Data.ByteString.Char8   as C
import           Data.Function           (on)
import           Data.IORef              (modifyIORef, newIORef, readIORef)
import           Data.List               (groupBy, sortBy)
import           Data.Ord                (comparing)
import           Data.TCP                (TCPHeader (..))
import           Network.Pcap            (PcapHandle, PktHdr, dispatch,
                                          openOffline, setFilter, toBS)
import           Network.Pharrell.Packets (Packet (..), parseByteString)

printPackets :: [(PktHdr, C.ByteString)] -> IO ()
printPackets xs = do
    let packets = map (parseByteString . snd) xs

    -- TODO: this "algorithm" depends on a sorted list to group tcp streams.
    -- This means that streaming input isn't going to work. Fine while we're
    -- exploring though.
    let sourceAndDestPort = (srcPort &&& dstPort) . tcpHeader
    let sortedPackets = sortBy (comparing sourceAndDestPort) packets
    let groupedPackets = groupBy ((==) `on` sourceAndDestPort) sortedPackets
    mapM_ (print . (sourceAndDestPort . head &&& length)) groupedPackets

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
