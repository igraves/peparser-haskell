module Data.PE.Utils where
import Data.Word
import Data.ByteString.Lazy 
import Data.ByteString.Internal
import Data.Binary.Get
import Data.Bits

--8byte string name
byte64String :: Word64 -> String
byte64String word = Prelude.map w2c (breakWord64 word)

--little endian
breakWord64 :: Word64 -> [Word8]
breakWord64 word = let x0 = (byte64 0 word) in
                   let x1 = (byte64 1 word) in
                   let x2 = (byte64 2 word) in
                   let x3 = (byte64 3 word) in
                   let x4 = (byte64 4 word) in
                   let x5 = (byte64 5 word) in
                   let x6 = (byte64 6 word) in
                   let x7 = (byte64 7 word) in
                   (cleanWord (x0:x1:x2:x3:x4:x5:x6:x7:[]))

cleanWord :: [Word8] -> [Word8]
cleanWord [] = []
cleanWord (x:ws) = if x == 0 then [] else [x] ++ (cleanWord ws)

--Stolen from http://www.mail-archive.com/haskell-cafe@haskell.org/msg69701.html
byte64 :: Int -> Word64 -> Word8
byte64 i w = fromIntegral (w `shiftR` (i * 8))

