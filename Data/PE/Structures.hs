module Data.PE.Structures where
import Data.Word
import Data.ByteString.Lazy
import Numeric
import Data.Binary
--import System.Time

-- |The over-arching container.  Holds the headers and a list of binary sections
data PEFile = PEFile {
    peHeader :: PEHeader
} deriving Show

data PEObject = PEObj {
    peObjHeader :: PEObjectHeader
} deriving Show

-- |The Binary Section container.  Holds names and containers.
data BinSection = BinSection {
    secname :: String,
    binSection :: ByteString
} deriving Show

data PEObjectHeader = PEObjHdr {
  objcoffhdr :: COFFHeader,
  objsectionTables :: [(SectionTable,ByteString)]
} deriving Show

-- |The Header section, holds entries for each header in the PE File
data PEHeader = PEHeader {
	msdosHeader :: MSDOSHeader,
	peSignature :: PESignature,
	coffHeader :: COFFHeader,
	standardFields :: StandardFields,
	windowsSpecFields :: WindowsSpecFields,
	dataDirectories :: [DirectoryEntry],
	sectionTables :: [(SectionTable,ByteString)]
--	sectionbytes :: [ByteString]
} deriving Show

data MSDOSHeader = MSDOSHeader {
	signature :: Word16,
	lastsize :: Word16,
	pagesInFile :: Word16,
	relocations :: Word16,
	headerSizeInParagraph :: Word16,
	minExtraParagraphs :: Word16,
	maxExtraParagraphs :: Word16,
	ss :: Word16,
	sp :: Word16,
	checksum :: Word16,
	ip :: Word16,
	cs :: Word16,
	relocTableOffset :: Word16,
	overlayNumber :: Word16,
	--4 * short reserved spaces
	oemIdentifier :: Word16,
	oemInformation :: Word16,
	--10 * short reserved spaces
	offset :: Word32
} 
instance Show MSDOSHeader where
	show header = "Signature: " ++ (show.encode $ signature header) ++ "\n"
		++ "Last Page Size: " ++ (show $ lastsize header) ++ "\n"
		++ "Number of Pages: " ++ (show $ pagesInFile header) ++ "\n"
		++ "Relocations: " ++ (show $ relocations header) ++ "\n"
		++ "Header Size in Paragraphs: " ++ (show $ headerSizeInParagraph header) ++ "\n"
		++ "Min Extra Paragraphs: " ++ (show $ minExtraParagraphs header) ++ "\n"
		++ "Max Extra Paragraphs: " ++ (show $ maxExtraParagraphs header) ++ "\n"
		++ "Stack Segment: 0x" ++ (showHex (ss header) "") ++ "\n"
		++ "Stack Pointer: 0x" ++ (showHex (sp header) "") ++ "\n"
		++ "File checksum: " ++ (show $ checksum header) ++ "\n"
		++ "Code Segment: " ++ (show $ cs header) ++ "\n"
		++ "Instruction Pointer: " ++ (show $ ip header) ++ "\n"
		++ "Relocation Offset: " ++ (show $ relocTableOffset header) ++ "\n"
		++ "Overlay Number: " ++ (show $ overlayNumber header) ++ "\n"
		++ "OEM Identifier: 0x" ++ (showHex (oemIdentifier header) "") ++ "\n"
		++ "OEM Information: 0x" ++(showHex (oemInformation header) "") ++ "\n"
		++ "PE Header Offset: " ++ (show $ offset header) ++ "\n"
		

data PESignature = PESignature {
	pesignature :: Word32 --0x00004550
} 
instance Show PESignature where
	show (PESignature sig) = "PE-Signature: 0x" ++ (showHex sig "") ++ "\n"

data COFFHeader = COFFHeader {
	targetMachine :: MachineType,
	numberOfSections :: Word16,  --IMPORTANT
	timeDateStamp :: Word32,
	pointerToSymbolTable :: Word32, --0 for image
	numberOfSymbols :: Word32, --0 for image
	sizeofOptionalHeaders :: Word16,
	coffCharacteristics :: Word16
}
instance Show COFFHeader where
	show hdr = "Target Machine: " ++ (show $ targetMachine hdr) ++"\n"
		++ "Number of Sections: " ++ (show (numberOfSections hdr)) ++"\n"
		++ "Timestamp: " ++ (show $ fromIntegral . timeDateStamp $ hdr) ++ "\n"
		++ "Symbol Table Pointer: 0x" ++ (showHex (pointerToSymbolTable hdr) "") ++ "\n"
		++ "Number of Symbols: " ++ (show $ numberOfSymbols hdr) ++ "\n"
		++ "Size of Optional Headers: " ++ (show $ sizeofOptionalHeaders hdr) ++ "\n"
		++ "COFF Characteristics: 0x" ++ (showHex (coffCharacteristics hdr) "") ++ "\n"

data StandardFields = StandardFields {
	standardSig :: Word16, -- Should be 0x10B or 0x20B if PE32+
	lnMajorVersion :: Word8,
	lnMinorVersion :: Word8,
	sizeOfCode :: Word32,
	sizeOfInitializedData :: Word32,
	sizeOfUninitData :: Word32,
	addressOfEntryPoint :: Word32,
	baseOfCode :: Word32,
	baseOfData :: Word32
} | SFPlus { standardSig :: Word16, 
              lnMajorVersion :: Word8,
              lnMinorVersion :: Word8,
              sizeOfCode :: Word32,
              sizeOfInitializedData :: Word32,
              sizeOfUninitData :: Word32,
              addressOfEntryPoint :: Word32, 
	            baseOfCode :: Word32 }

instance Show StandardFields where
	show sf = "Signature: 0x" ++ (showHex (standardSig sf) "") ++ "\n"
		++ "Linker Major Version: " ++ (show $ lnMajorVersion sf) ++ "\n"
		++ "Linker Minor Version: " ++ (show $ lnMinorVersion sf) ++ "\n"
		++ "Size of Code: " ++ (show $ sizeOfCode sf) ++ "\n"
		++ "Size of Initialized Data: " ++ (show $ sizeOfInitializedData sf) ++ "\n"
		++ "Size of Un-initialized Data: " ++ (show $ sizeOfUninitData sf) ++ "\n"
		++ "Entry Point Address: 0x" ++ (showHex (addressOfEntryPoint sf) "") ++ "\n"
		++ "Code base Address: 0x" ++ (showHex (baseOfCode sf) "") ++ "\n"
		-- ++"Data base Address: 0x"++(showHex (baseOfData sf) "")++"\n"

data WindowsSpecFields = WindowsSpecFields {
	imageBase :: Word32,
	sectionAlignment :: Word32,
	fileAlignment :: Word32,
	majorOSVersion :: Word16,
	minorOSVersion :: Word16,
	majorImageVersion :: Word16,
	minorImageVersion :: Word16,
	majorSubSystemVersion :: Word16,
	minorSubSystemVersion :: Word16,
	win32VersionValue :: Word32,
	sizeOfImage :: Word32,
	sizeOfHeaders :: Word32,
	checkSum32 :: Word32,
	checkSum16 :: Word16,
	dllCharacteristics :: Word16,
	sizeOfStackReserve :: Word32,
	sizeOfStackCommit :: Word32,
	sizeOfHeapReserve :: Word32,
	sizeOfHeapCommit :: Word32,
	loaderFlags :: Word32,
	numberOfRVAandSizes :: Word32
} | WSFPlus { imgBase :: Word64,
            sectionAlignment :: Word32,
            fileAlignment :: Word32,
            majorOSVersion :: Word16,
            minorOSVersion :: Word16,
            majorImageVersion :: Word16,
            minorImageVersion :: Word16,
            majorSubSystemVersion :: Word16,
            minorSubSystemVersion :: Word16,
            win32VersionValue :: Word32,
            sizeOfImage :: Word32,
            sizeOfHeaders :: Word32,
            checkSum32 :: Word32,
            checkSum16 :: Word16,
            dllCharacteristics :: Word16,
            szOfStackReserve :: Word64,
            szOfStackCommit :: Word64,
            szOfHeapReserve :: Word64,
            szOfHeapCommit :: Word64,
            loaderFlags :: Word32,
            numberOfRVAandSizes :: Word32 }

instance Show WindowsSpecFields where
	show hdr = "Image Base: 0x" ++ (showHex (imageBase hdr) "") ++ "\n"
		++ "Section Alignment: 0x" ++ (showHex (sectionAlignment hdr) "") ++ "\n"
		++ "File Alignment: 0x" ++ (showHex (fileAlignment hdr) "") ++ "\n"
		++ "Major OS Version: " ++ (show $ majorOSVersion hdr) ++ "\n"
		++ "Minor OS Version: " ++ (show $ minorOSVersion hdr) ++ "\n"
		++ "Major Subsystem Version: " ++ (show $ majorSubSystemVersion hdr) ++ "\n"
		++ "Minor Subsystem Version: " ++ (show $ minorSubSystemVersion hdr) ++ "\n"
		++ "Win 32 Version Value: " ++ (show $ win32VersionValue hdr) ++ "\n"
		++ "Size of Image: " ++ (show $ sizeOfImage hdr) ++ "\n"
		++ "Size of Headers: " ++ (show $ sizeOfHeaders hdr) ++ "\n"
		++ "Checksum 32: " ++ (show $ checkSum32 hdr) ++ "\n"
		++ "Checksum 15: " ++ (show $ checkSum16 hdr) ++ "\n"
		++ "DLL Characteristics: 0x" ++ (showHex (dllCharacteristics hdr) "") ++ "\n"
		++ "Size of Stack Reserved: " ++ (show $ sizeOfStackReserve hdr) ++ "\n"
		++ "Size of Stack Commit: " ++ (show $ sizeOfStackCommit hdr) ++ "\n"
		++ "Size of Heap Reserved: " ++ (show $ sizeOfHeapReserve hdr) ++ "\n"
		++ "Size of Heap Commit: " ++ (show $ sizeOfHeapCommit hdr) ++ "\n"
		++ "Loader Flags: 0x" ++ (showHex (loaderFlags hdr) "") ++ "\n"
		++ "RVA: " ++ (show $ numberOfRVAandSizes hdr) ++ "\n"


data DirectoryEntry = DirEntry {
  virtualAddr :: Word32,
  entrySize :: Word32
} deriving Show

data SectionTable = SectionTable {
	sectionHeaderName :: String,
	virtualSize :: Word32,
	virtualAddress :: Word32,
	sizeOfRawData :: Word32,
	pointerToRawData :: Word32,
	pointerToRelocations :: Word32,
	pointerToLineNumbers :: Word32,
	numberOfRelocations :: Word16,
	numberOfLineNumbers :: Word16,
	secCharacteristics :: Word32
} deriving Show

data MachineType = UNKNOWN | AM33 | AMD64 | ARM | ARMV7 | EBC | I386 | IA64 | M32R | MIPS16 | MIPSFPU | MIPSFPU16 |
                    PPC | PPCFP | R4000 | SH3 | SH3DSP | SH4 | SH5 | THUMB | WCE | INVALID deriving Show

mapMachine :: Word16 -> MachineType
mapMachine w = case w of
                   0x00 -> UNKNOWN
                   0x1d3 -> AM33
                   0x8664 -> AMD64
                   0x1c0 -> ARM
                   0x1c4 -> ARMV7
                   0xebc -> EBC
                   0x14c -> I386
                   0x200 -> IA64
                   0x9041 -> M32R
                   0x266 -> MIPS16
                   0x366 -> MIPSFPU
                   0x466 -> MIPSFPU16
                   0x1f0 -> PPC
                   0x1f1 -> PPCFP
                   0x166 -> R4000
                   0x1a2 -> SH3
                   0x1a3 -> SH3DSP
                   0x1a6 -> SH4
                   0x1a8 -> SH5
                   0x1c2 -> THUMB
                   0x169 -> WCE
