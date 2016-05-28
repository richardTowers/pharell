module Network.Pharell.Lib ( readPcap ) where

import qualified Data.ByteString.Char8 as C
import           Data.IORef
import           Data.IP
import           Data.Serialize        (decode)
import           Data.TCP
import           Network.Pcap

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
stripIpHeader bs = case decode bs of
    Left  msg -> error msg
    Right hdr -> (hdr, C.drop (4 * hdrLength hdr) bs)

stripTcpHeader :: C.ByteString -> (TCPHeader, C.ByteString)
stripTcpHeader bs = case decode bs of
    Left  msg -> error msg
    Right hdr -> (hdr, C.drop (4 * dataOffset hdr) bs)

readPcap :: IO ()
readPcap = do
    handle <- openOffline "example.pcap"
    setFilter handle pcapFilter True 0xff
    packetStore <- newIORef []
    _ <- dispatch handle (-1) (pcapCallback $ storePacket packetStore)
    reverse <$> readIORef packetStore >>= printPcap
    where pcapFilter = "tcp and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)"

storePacket :: IORef [(PktHdr, C.ByteString)] -> (PktHdr, C.ByteString) -> IO ()
storePacket ioRef packetList = modifyIORef ioRef (packetList:)

pcapCallback :: ((PktHdr, C.ByteString) -> IO ()) -> Callback
pcapCallback store header word = toBS (header, word) >>= store
