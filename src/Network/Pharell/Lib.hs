module Network.Pharell.Lib ( readPcap ) where

import qualified Data.ByteString.Char8 as C
import           Data.IORef
import           Network.Pcap
import           Network.Pharell.Packets

printPcap :: [(PktHdr, C.ByteString)] -> IO ()
printPcap xs = do
    let (_, bdy) = head xs
    let (ipHdr, tcpHdr, httpMessage) = parseByteString bdy
    putStrLn "\nIP Header\n---------------"
    print ipHdr
    putStrLn "\nTCP Header\n---------------"
    print tcpHdr
    putStrLn "\nHTTP Message\n---------------"
    C.putStrLn httpMessage

readPcap :: IO ()
readPcap = do
    handle <- openOffline "example.pcap"
    setFilter handle ipv4HttpFilter True 0xff
    readPcapFile handle >>= printPcap
    where ipv4HttpFilter = "tcp and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)"

readPcapFile :: PcapHandle -> IO [(PktHdr, C.ByteString)]
readPcapFile handle = do
    packetStore <- newIORef []
    _ <- dispatch handle (-1) (callback (\x -> modifyIORef packetStore (x:)))
    reverse <$> readIORef packetStore
    where callback store hdr wrd = toBS (hdr, wrd) >>= store
