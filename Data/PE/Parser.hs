module Data.PE.Parser (buildFile, buildFileFromBS) where
import Data.PE.Structures
import Data.PE.Utils
import Data.Word
import qualified Data.ByteString.Lazy as B
import Data.Binary.Get

-- |Supply a filename of a PE file in the form of a string.  Returns a PEFile structure
buildFile :: String -- ^The file name
             -> IO (PEFile) -- ^The resulting data structure in the IO monad
buildFile fName = do
                      fbstring <- B.readFile fName
                      return $ buildFileFromBS fbstring 

-- |Supply a bytestring to be parsed as if it were a PE Binary.  Returns a PEFile structure
buildFileFromBS :: B.ByteString  -- ^ByteString representing a PE file
             -> PEFile -- ^The data structure returned
buildFileFromBS fbstring =
                            let peheader = (runGet header fbstring) in
                            let mapSections = \sections -> (secBytes fbstring sections) in
                            let secTables = sectionTables peheader in
                            let binsections = map mapSections secTables in
                             PEFile{peHeader=peheader, bSections=binsections}

header :: Get (PEHeader)
header = do
                  dosheader <- buildMSDOSHead
                  bytes <- bytesRead
                  let peoffset = (fromIntegral (offset dosheader)) - (fromIntegral bytes)
                  skip peoffset
                  peSig <- buildPESignature
                  coff <- buildCOFFHeader
                  sfheader <- buildSFHeader
                  wsfheader <- buildWSFHeader
                  datadirs <- buildDataDirectories
                  let numsections = fromIntegral (numberOfSections coff)
                  sectables <- sections numsections
                  return PEHeader {msdosHeader=dosheader, peSignature=peSig, coffHeader=coff, standardFields=sfheader,
                                  windowsSpecFields=wsfheader, dataDirectories=datadirs, sectionTables=sectables}

sections :: Int -> Get ([SectionTable])
sections 0 = return []
sections n = sections (n - 1) >>= \rest -> buildSectionTable >>= \item -> return (item:rest)

secBytes :: B.ByteString -> SectionTable -> BinSection
secBytes bs sec = let offset = (fromIntegral . pointerToRawData) sec in
                  let size = (fromIntegral . sizeOfRawData) sec in
                  let name = (byte64String . sectionHeaderName) sec in
                  let pbs = B.drop offset bs in
                  let sbs = B.take size pbs in
                  BinSection {secname=name, binSection=sbs}

buildMSDOSHead :: Get (MSDOSHeader)
buildMSDOSHead = do
                    signature' <- getWord16le
                    lastsize' <- getWord16le
                    pagesInFile' <- getWord16le
                    relocations' <- getWord16le
                    headerSizeInParagraph' <- getWord16le
                    minExtraParagraphs' <- getWord16le
                    maxExtraParagraphs' <- getWord16le
                    ss' <- getWord16le
                    sp' <- getWord16le
                    checksum' <- getWord16le
                    ip' <- getWord16le
                    cs' <- getWord16le
                    relocTableOffset' <- getWord16le
                    overlayNumber' <- getWord16le
                    getWord16le -- chew through
                    getWord16le
                    getWord16le
                    getWord16le
                    oemIdentifier' <- getWord16le
                    oemInformation' <- getWord16le
                    getWord32le -- chew through, there are actually 10 16-bit reserved slots, 32 here for brevity
                    getWord32le
                    getWord32le
                    getWord32le
                    getWord32le
                    offset' <- getWord32le -- this should be 0x80, we could check later if we wanted to
                    let header = MSDOSHeader {signature=signature', lastsize=lastsize', pagesInFile=pagesInFile',
                                              relocations=relocations', headerSizeInParagraph=headerSizeInParagraph',
                                              minExtraParagraphs=minExtraParagraphs', maxExtraParagraphs=maxExtraParagraphs',
                                              ss=ss', sp=sp', checksum=checksum', ip=ip', cs=cs', 
                                              relocTableOffset=relocTableOffset', overlayNumber=overlayNumber',
                                              oemIdentifier=oemIdentifier', oemInformation=oemInformation', offset=offset'}
                        
                    return header 

buildPESignature :: Get (PESignature)
buildPESignature = do
                    sig <- getWord32le
                    return PESignature { pesignature=sig }

buildCOFFHeader :: Get (COFFHeader)
buildCOFFHeader = do
                    targetMachine' <- getWord16le
                    numberOfSections' <- getWord16le
                    timeDateStamp' <- getWord32le
                    pointerToSymbolTable' <- getWord32le
                    numberOfSymbols' <- getWord32le
                    sizeofOptionalHeaders' <- getWord16le
                    coffCharacteristics' <- getWord16le
                    let header = COFFHeader { targetMachine=targetMachine', numberOfSections=numberOfSections',
                                              timeDateStamp=timeDateStamp', pointerToSymbolTable=pointerToSymbolTable',
                                              numberOfSymbols=numberOfSymbols', sizeofOptionalHeaders=sizeofOptionalHeaders',
                                              coffCharacteristics=coffCharacteristics'}
                    return header





buildSFHeader :: Get (StandardFields)
buildSFHeader = do
                   standardSig' <- getWord16le
                   lnMajorVersion' <- getWord8
                   lnMinorVersion' <- getWord8
                   sizeOfCode' <- getWord32le
                   sizeOfInitializedData' <- getWord32le
                   sizeOfUninitData' <- getWord32le
                   addressOfEntryPoint' <- getWord32le
                   baseOfCode' <- getWord32le
                   baseOfData' <- getWord32le
                   let header = StandardFields { standardSig=standardSig', lnMajorVersion=lnMajorVersion',
                                               lnMinorVersion=lnMinorVersion', sizeOfCode=sizeOfCode', sizeOfInitializedData=sizeOfInitializedData',
                                               sizeOfUninitData=sizeOfUninitData', addressOfEntryPoint=addressOfEntryPoint',
                                               baseOfCode=baseOfCode', baseOfData=baseOfData'}
                   return header



buildWSFHeader :: Get (WindowsSpecFields)
buildWSFHeader = do
                    imageBase' <- getWord32le
                    sectionAlignment' <- getWord32le
                    fileAlignment' <- getWord32le
                    majorOSVersion' <- getWord16le
                    minorOSVersion' <- getWord16le
                    majorImageVersion' <- getWord16le
                    minorImageVersion' <- getWord16le
                    majorSubSystemVersion' <- getWord16le
                    minorSubSystemVersion' <- getWord16le
                    win32VersionValue' <- getWord32le
                    sizeOfImage' <- getWord32le
                    sizeOfHeaders' <- getWord32le
                    checkSum32' <- getWord32le
                    checkSum16' <- getWord16le
                    dllCharacteristics' <- getWord16le
                    sizeOfStackReserve' <- getWord32le
                    sizeOfStackCommit' <- getWord32le
                    sizeOfHeapReserve' <- getWord32le
                    sizeOfHeapCommit' <- getWord32le
                    loaderFlags' <- getWord32le
                    numberOfRVAandSizes' <- getWord32le
                    let header = WindowsSpecFields { imageBase=imageBase', sectionAlignment=sectionAlignment',
                                                     fileAlignment=fileAlignment', majorOSVersion=majorOSVersion',
                                                     minorOSVersion=minorOSVersion', majorImageVersion=majorImageVersion',
                                                     minorImageVersion=minorImageVersion', majorSubSystemVersion=majorSubSystemVersion',
                                                     minorSubSystemVersion=minorSubSystemVersion', win32VersionValue=win32VersionValue',
                                                     sizeOfImage=sizeOfImage', sizeOfHeaders=sizeOfHeaders', checkSum32=checkSum32',
                                                     checkSum16=checkSum16', dllCharacteristics=dllCharacteristics', sizeOfStackReserve=sizeOfStackReserve',
                                                     sizeOfStackCommit=sizeOfStackCommit', sizeOfHeapReserve=sizeOfHeapReserve', 
                                                     sizeOfHeapCommit=sizeOfHeapCommit', loaderFlags=loaderFlags', numberOfRVAandSizes=numberOfRVAandSizes' }
                    return header



buildDataDirectories :: Get (DataDirectories)
buildDataDirectories = do
                        edataOffset' <- getWord32le
                        edataSize' <- getWord32le
                        idataOffset' <- getWord32le
                        idataSize' <- getWord32le
                        rsrcOffset' <- getWord32le
                        rsrcSize' <- getWord32le
                        pdataOffset' <- getWord32le
                        pdataSize' <- getWord32le
                        attrCertOffset' <- getWord32le
                        attrCertSize' <- getWord32le
                        relocOffset' <- getWord32le
                        relocSize' <- getWord32le
                        debugOffset' <- getWord32le
                        debugSize' <- getWord32le
                        architecture1' <- getWord32le
                        architecture2' <- getWord32le
                        globalPtrOffset' <- getWord32le
                        getWord32le
                        tlsOffset' <- getWord32le
                        tlsSize' <- getWord32le
                        loadCfgTableOffset' <- getWord32le
                        loadConfigTableSize' <- getWord32le
                        boundImportTableOffset' <- getWord32le
                        boundImportTableSize' <- getWord32le
                        importAddressTableOffset' <- getWord32le
                        importAddressTableSize' <- getWord32le
                        delayImportDescriptorOffset' <- getWord32le
                        delayImportDescriptorSize' <- getWord32le
                        clrRuntimeHeaderOffset' <- getWord32le
                        clrRuntimeHeaderSize' <- getWord32le
                        getWord32le
                        getWord32le
                        let header = DataDirectories { edataOffset=edataOffset', edataSize=edataOffset', idataOffset=idataOffset',
                                                       idataSize=idataSize', rsrcOffset=rsrcOffset', rsrcSize=rsrcSize', pdataOffset=pdataOffset',
                                                       pdataSize=pdataSize', attrCertOffset=attrCertOffset', attrCertSize=attrCertSize', 
                                                       relocOffset=relocOffset', relocSize=relocSize', debugOffset=debugOffset',
                                                       debugSize=debugSize', architecture1=architecture1', architecture2=architecture2',
                                                       globalPtrOffset=globalPtrOffset', tlsOffset=tlsOffset', tlsSize=tlsSize', 
                                                       loadCfgTableOffset=loadCfgTableOffset', loadConfigTableSize=loadConfigTableSize',
                                                       boundImportTableOffset=boundImportTableOffset', boundImportTableSize=boundImportTableSize',
                                                       importAddressTableOffset=importAddressTableOffset', importAddressTableSize=importAddressTableSize',
                                                       delayImportDescriptorOffset=delayImportDescriptorOffset', delayImportDescriptorSize=delayImportDescriptorSize',
                                                       clrRuntimeHeaderOffset=clrRuntimeHeaderOffset', clrRuntimeHeaderSize=clrRuntimeHeaderSize'}
                        return header



buildSectionTable :: Get (SectionTable)
buildSectionTable = do
                       sectionHeaderName' <- getWord64le
                       virtualSize' <- getWord32le
                       virtualAddress' <- getWord32le
                       sizeOfRawData' <- getWord32le
                       pointerToRawData' <- getWord32le
                       pointerToRelocations' <- getWord32le
                       pointerToLineNumbers' <- getWord32le
                       numberOfRelocations' <- getWord16le
                       numberOfLineNumbers' <- getWord16le
                       secCharacteristics' <- getWord32le
                       let header = SectionTable { sectionHeaderName=sectionHeaderName', virtualSize=virtualSize',
                                                   virtualAddress=virtualAddress', sizeOfRawData=sizeOfRawData',
                                                   pointerToRawData=pointerToRawData', pointerToRelocations=pointerToRelocations',
                                                   pointerToLineNumbers=pointerToLineNumbers', numberOfRelocations=numberOfRelocations',
                                                   numberOfLineNumbers=numberOfLineNumbers', secCharacteristics=secCharacteristics'}
                       return header


