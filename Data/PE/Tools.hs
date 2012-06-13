module Data.PE.Tools where
import Data.PE.Parser
import Data.PE.Structures
import qualified Data.ByteString.Lazy as LBS
import Data.Word
import System.IO.Unsafe
import Data.Binary
import Data.Binary.Get
import Data.Char
import Data.Bits
import Data.Array.Unboxed
import Data.List

type Filename = String
type Secname = String
type SectionMeta = (SectionTable, LBS.ByteString)

getsecandinfo :: Filename -> Secname -> IO ((Maybe SectionMeta, MachineType))
getsecandinfo fn sn = buildFile fn >>= \pefile -> return (getsection pefile sn, getmachinetype pefile)

getsec :: Filename -> Secname -> IO (Maybe SectionMeta)
getsec fn sn = buildFile fn >>= \pefile -> return $ getsection pefile sn

getsecs :: Filename -> [SectionMeta]
getsecs fn = unsafePerformIO (buildFile fn >>= \pefile -> return $ (sectionTables.peHeader) pefile)

getary :: Filename -> UArray Word32 Word8
getary fn = arrayrep $ getsecs fn

getdirs :: Filename -> [DirectoryEntry]
getdirs fn = unsafePerformIO (buildFile fn >>= \pefile -> return $ (dataDirectories.peHeader) pefile)

getsection :: PEFile -> Secname -> Maybe SectionMeta
getsection pefile secn = let sections = (sectionTables.peHeader) pefile in
                          find (\x -> secn == (sectionHeaderName $ fst x)) sections 

getmachinetype :: PEFile -> MachineType
getmachinetype pe = targetMachine $ coffHeader $ peHeader pe

showsections :: Filename -> IO ()
showsections filename = do
                           pefile <- buildFile filename
                           let sections = (sectionTables.peHeader) pefile
                           let coff = (coffHeader.peHeader) pefile
                           let std = (standardFields.peHeader) pefile
                           let showme = \x -> (sectionHeaderName $ fst x)
                           --putStr $ show datadirs
                           putStr $ show $ coff
                           putStr $ show $ std
                           putStr $ show $ map showme sections 
                           --putStr $ show $ (numberOfRVAandSizes.windowsSpecFields.peHeader) pefile
                           --putStr $ show pefile
                           return () 


--Import Table Parsing stuff.  This should eventually move to the PE library.

type ImportDirectory = [ImportDirectoryEntry]
type ImportLookupTable = [ImportLookupTableEntry]

data ImportDirectoryEntry = ID {
                                lookupTableRVA :: Word32,
                                timeStamp :: Word32,
                                forwarderChain :: Word32,
                                nameRVA :: Word32,
                                importAddressTableRVA :: Word32
                               } | IDNull deriving (Show,Eq)

data HintNameEntry = HNE { 
                           hint :: Word16,
                           name :: String
                         } deriving (Show, Eq)

data ImportLookupTableEntry = ILTOrd Word16 | ILTHint Word32 | ILTNull deriving (Show,Eq)


getImpDir :: Get ImportDirectory
getImpDir = do
              entry <- get
              case (entry) of
                   IDNull -> return [IDNull]
                   x      -> getImpDir >>= \y -> return (x : y)


getLT :: Get ImportLookupTable
getLT = do
           entry <- get
           case (entry) of
                ILTNull -> return [ILTNull]
                x       -> getLT >>= \y -> return (x : y)


instance Binary HintNameEntry where
      put (HNE h n) = let words' = (map fromIntegral $ map ord n)::[Word8] in
                       do 
                        put h
                        put words'
                        if (length words' `mod` 2 == 0) 
                          then put (0x0::Word8)
                          else return ()
      get = do
               ordinal <- getWord16le
               astr <- getAStr
               if (length astr `mod` 2 == 0)
                 then getWord8 >>= \_ -> return (HNE ordinal astr)
                 else return (HNE ordinal astr)

instance Binary ImportDirectoryEntry where
    put (ID lut ts fc nrva iarva) = put lut >> put ts >> put fc >> put nrva >> put iarva
    put (IDNull) = put (0x0::Word32) >> put (0x0::Word32) >> put (0x0::Word32) >> put (0x0::Word32) >> put (0x0::Word32)
    get = do
            lut <- getWord32le
            ts <- getWord32le
            fc <- getWord32le
            nrva <- getWord32le
            iarva <- getWord32le
            case (lut + ts + fc + nrva + iarva) of
                    0 -> return IDNull
                    _ -> return (ID lut ts fc nrva iarva)

instance Binary ImportLookupTableEntry where
   put (ILTOrd ord') = put (0x80::Word8) >> put ord' >> put (0x00::Word8)
   put (ILTHint rva) = put (setBit rva 31)
   put ILTNull = put (0x0::Word32)
   get = do
            word <- getWord32le
            case (word) of
                0 -> return ILTNull
                _ -> case (testBit word 31) of
                          True  -> return $ ILTOrd $ fromIntegral word
                          False -> return $ ILTHint (clearBit word 31)
--More PE Data structure stuff
importInfo :: Filename -> [([Char], [String])]
importInfo fn = importInfo' (getsecs fn) (getdirs fn)

importInfo' :: [SectionMeta] -> [DirectoryEntry] -> [([Char], [String])]
importInfo' secns dirs = map infos ientries 
                where ary = arrayrep secns
                      ientries = delete IDNull $  buildImport ary dirs
                      lookups = (buildLookup ary) 
                      hnts = (buildHintName ary) 
                      infos = \x -> (getdllname ary x, map name $ map hnts $ delete ILTNull $ lookups x)

--Build the Import table.
buildImport :: UArray Word32 Word8 -> [DirectoryEntry] -> ImportDirectory
buildImport ary dirs = runGet getImpDir bstr  
                where itaddr = virtualAddr (dirs !! 1)
                      bstr = grabAt (fromIntegral itaddr) ary
                      
buildLookup :: UArray Word32 Word8 -> ImportDirectoryEntry -> ImportLookupTable
buildLookup ary ientry = runGet getLT (grabAt (fromIntegral rva) ary)
                where rva = lookupTableRVA ientry

buildHintName :: UArray Word32 Word8 -> ImportLookupTableEntry -> HintNameEntry
buildHintName ary ltentry = case (ltentry) of
                                  (ILTHint x) -> runGet hnte (grabAt (fromIntegral x) ary)
                                  (ILTNull) -> error "Null encountered"
                                  _ -> error "Not working with ords today"
                where hnte = get >>= \x -> return x::Get HintNameEntry

getdllname :: UArray Word32 Word8 -> ImportDirectoryEntry -> [Char]
getdllname ary ientry = case (ientry) of
                             (IDNull) -> ""
                             _        -> runGet getAStr (grabAt (fromIntegral rva) ary) 
                where rva = nameRVA ientry
--Building an array to represent the file structure
sectoblist :: Num a => (SectionTable, LBS.ByteString) -> [(a, Word8)]
sectoblist (secn, bytes) = let words' = LBS.unpack bytes in
                           let indxs x = x : indxs (x+1) in
                            zip (indxs $ fromIntegral $ virtualAddress secn) words'

arrayrep :: [SectionMeta] -> UArray Word32 Word8
arrayrep secn = array (0,maxaddr) words'
        where
          words' = concat $ map sectoblist secn
          maxaddr = maximum $ map fst words'

--Ask for an address to begin a new head for a bytestring to build from, simple enough.
{-
grabAt :: Word32 -> UArray Word32 Word8 -> LBS.ByteString
grabAt indx ary = LBS.pack $ elems newarray 
        where maxdx = maximum $ indices ary
              newarray = ixmap (0,maxdx-indx) (\i -> i - indx) ary --remap the array
-}
grabAt :: Int -> UArray Word32 Word8 -> LBS.ByteString
grabAt indx ary = LBS.pack $ drop (indx) $ elems ary
