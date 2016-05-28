module Network.Pharell.Lib ( readPcap ) where

import qualified Data.ByteString.Char8 as C
import           Data.IORef
import           Data.IP
import           Data.TCP
import           Data.Serialize        (decode)
import           Network.Pcap

printPcap :: [(PktHdr, C.ByteString)] -> IO ()
printPcap xs = do
    let (_, bdy) = head xs
    let goodBdy = C.drop 4 bdy
    case decodeIPv4Header goodBdy of
        (Left str) -> error str
        (Right header) -> do
            print header
            thing <- doTheThing header goodBdy
            C.putStrLn thing

doTheThing :: IPv4Header -> C.ByteString -> IO C.ByteString
doTheThing header bdy = do
    let tcpBdy = C.drop (4 * hdrLength header) bdy
    case decodeTcpHeader tcpBdy of
        (Left str) -> error str
        (Right header) -> do
            print header
            return $ C.drop (4 * dataOffset header) tcpBdy

decodeIPv4Header :: C.ByteString -> Either String IPv4Header
decodeIPv4Header = decode

decodeTcpHeader :: C.ByteString -> Either String TCPHeader
decodeTcpHeader = decode

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
