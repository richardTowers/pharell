module Network.Pharell.Lib ( readPcap ) where

import qualified Data.ByteString.Char8 as C
import           Data.IORef
import           Data.IP
import           Data.TCP
import           Data.Serialize        (decode)
import           Network.Pcap

right :: Either String b -> b
right (Left x) = error x
right (Right x) = x

printPcap :: [(PktHdr, C.ByteString)] -> IO ()
printPcap xs = do
    let (_, bdy) = head xs
    let ipBdy = C.drop 4 bdy
    let (ipHdr, tcpBdy) = stripIpHeader ipBdy
    let (tcpHdr, httpMessage) = stripTcpHeader tcpBdy
    putStrLn "\nIP Header\n---------------"
    print ipHdr
    putStrLn "\nTCP Header\n---------------"
    print tcpHdr
    putStrLn "\nHTTP Message\n---------------"
    C.putStrLn httpMessage

stripIpHeader :: C.ByteString -> (IPv4Header, C.ByteString)
stripIpHeader bs = do
    let hdr = right $ decode bs :: IPv4Header
    let bdy = C.drop (4 * hdrLength hdr) bs
    (hdr, bdy)

stripTcpHeader :: C.ByteString -> (TCPHeader, C.ByteString)
stripTcpHeader bs = do
    let hdr = right $ decode bs :: TCPHeader
    let bdy = C.drop (4 * dataOffset hdr) bs
    (hdr, bdy)

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
