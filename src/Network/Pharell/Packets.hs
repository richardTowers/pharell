module Network.Pharell.Packets ( parseByteString, Packet(..) ) where

import qualified Data.ByteString.Char8 as C
import           Data.IP
import           Data.Serialize        (decode)
import           Data.TCP

data Packet = Packet {
    ipv4Header :: IPv4Header,
    tcpHeader  :: TCPHeader,
    body       :: C.ByteString
} deriving Show

parseByteString :: C.ByteString -> Packet
parseByteString bs = do
    let ipBs = stripLinkLayerHeader bs
    let (ipHdr, tcpBs) = stripIpHeader ipBs
    let (tcpHdr, httpBs) = stripTcpHeader tcpBs
    Packet ipHdr tcpHdr httpBs

-- |Drops the link layer header. For loopback on OS X this is 4 bytes.
-- TODO: what about ethernet / other OSs?
stripLinkLayerHeader :: C.ByteString -> C.ByteString
stripLinkLayerHeader = C.drop 4

stripIpHeader :: C.ByteString -> (IPv4Header, C.ByteString)
stripIpHeader bs = case decode bs of
    Left  msg -> error msg
    Right hdr -> (hdr, C.drop (4 * hdrLength hdr) bs)

stripTcpHeader :: C.ByteString -> (TCPHeader, C.ByteString)
stripTcpHeader bs = case decode bs of
    Left  msg -> error msg
    Right hdr -> (hdr, C.drop (4 * dataOffset hdr) bs)
