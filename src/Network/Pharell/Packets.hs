module Network.Pharell.Packets ( parseByteString ) where

import qualified Data.ByteString.Char8 as C
import           Data.IP
import           Data.Serialize        (decode)
import           Data.TCP

parseByteString :: C.ByteString -> (IPv4Header, TCPHeader, C.ByteString)
parseByteString bs = do
    let ipBs = stripLinkLayerHeader bs
    let (ipHdr, tcpBs) = stripIpHeader ipBs
    let (tcpHdr, httpBs) = stripTcpHeader tcpBs
    (ipHdr, tcpHdr, httpBs)

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
