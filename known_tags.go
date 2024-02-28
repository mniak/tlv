package tlv

var tagNames = map[Tag]string{
	Tag(0x42):   "Issuer Identification Number (IIN)",
	Tag(0x4F):   "Application Identifier (AID) – card",
	Tag(0x50):   "Application Label",
	Tag(0x57):   "Track 2 Equivalent Data",
	Tag(0x5A):   "Application Primary Account Number (PAN)",
	Tag(0x5F20): "Cardholder Name",
	Tag(0x5F24): "Application Expiration Date",
	Tag(0x5F25): "Application Effective Date",
	Tag(0x5F28): "Issuer Country Code",
	Tag(0x5F2A): "Transaction Currency Code",
	Tag(0x5F2D): "Language Preference",
	Tag(0x5F30): "Service Code",
	Tag(0x5F34): "Application Primary Account Number (PAN) Sequence Number",
	Tag(0x5F36): "Transaction Currency Exponent",
	Tag(0x5F50): "Issuer URL",
	Tag(0x5F53): "International Bank Account Number (IBAN)",
	Tag(0x5F54): "Bank Identifier Code (BIC)",
	Tag(0x5F55): "Issuer Country Code (alpha2 format)",
	Tag(0x5F56): "Issuer Country Code (alpha3 format)",
	Tag(0x61):   "Application Template",
	Tag(0x6F):   "File Control Information (FCI) Template",
	Tag(0x70):   "EMV Proprietary Template",
	Tag(0x71):   "Issuer Script Template 1",
	Tag(0x72):   "Issuer Script Template 2",
	Tag(0x73):   "Directory Discretionary Template",
	Tag(0x77):   "Response Message Template Format 2",
	Tag(0x80):   "Response Message Template Format 1",
	Tag(0x81):   "Amount, Authorised (Binary)",
	Tag(0x82):   "Application Interchange Profile",
	Tag(0x83):   "Command Template",
	Tag(0x84):   "Dedicated File (DF) Name",
	Tag(0x86):   "Issuer Script Command",
	Tag(0x87):   "Application Priority Indicator",
	Tag(0x88):   "Short File Identifier (SFI)",
	Tag(0x89):   "Authorisation Code",
	Tag(0x8A):   "Authorisation Response Code",
	Tag(0x8C):   "Card Risk Management Data Object List 1 (CDOL1)",
	Tag(0x8D):   "Card Risk Management Data Object List 2 (CDOL2)",
	Tag(0x8E):   "Cardholder Verification Method (CVM) List",
	Tag(0x8F):   "Certification Authority Public Key Index",
	Tag(0x90):   "Issuer Public Key Certificate",
	Tag(0x91):   "Issuer Authentication Data",
	Tag(0x92):   "Issuer Public Key Remainder",
	Tag(0x93):   "Signed Static Application Data",
	Tag(0x94):   "Application File Locator (AFL)",
	Tag(0x95):   "Terminal Verification Results",
	Tag(0x97):   "Transaction Certificate Data Object List (TDOL)",
	Tag(0x98):   "Transaction Certificate (TC) Hash Value",
	Tag(0x99):   "Transaction Personal Identification Number (PIN) Data",
	Tag(0x9A):   "Transaction Date",
	Tag(0x9B):   "Transaction Status Information",
	Tag(0x9C):   "Transaction Type",
	Tag(0x9D):   "Directory Definition File (DDF) Name",
	Tag(0x9F01): "Acquirer Identifier",
	Tag(0x9F02): "Amount, Authorised (Numeric)",
	Tag(0x9F03): "Amount, Other (Numeric)",
	Tag(0x9F04): "Amount, Other (Binary)",
	Tag(0x9F05): "Application Discretionary Data",
	Tag(0x9F06): "Application Identifier (AID) – terminal",
	Tag(0x9F07): "Application Usage Control",
	Tag(0x9F08): "Application Version Number",
	Tag(0x9F09): "Application Version Number",
	Tag(0x9F0B): "Cardholder Name Extended",
	Tag(0x9F0D): "Issuer Action Code – Default",
	Tag(0x9F0E): "Issuer Action Code – Denial",
	Tag(0x9F0F): "Issuer Action Code – Online",
	Tag(0x9F10): "Issuer Application Data",
	Tag(0x9F11): "Issuer Code Table Index",
	Tag(0x9F12): "Application Preferred Name",
	Tag(0x9F13): "Last Online Application Transaction Counter (ATC) Register",
	Tag(0x9F14): "Lower Consecutive Offline Limit",
	Tag(0x9F15): "Merchant Category Code",
	Tag(0x9F16): "Merchant Identifier",
	Tag(0x9F17): "Personal Identification Number (PIN) Try Counter",
	Tag(0x9F18): "Issuer Script Identifier",
	Tag(0x9F1A): "Terminal Country Code",
	Tag(0x9F1B): "Terminal Floor Limit",
	Tag(0x9F1C): "Terminal Identification",
	Tag(0x9F1D): "Terminal Risk Management Data",
	Tag(0x9F1E): "Interface Device (IFD) Serial Number",
	Tag(0x9F1F): "Track 1 Discretionary Data",
	Tag(0x9F20): "Track 2 Discretionary Data",
	Tag(0x9F21): "Transaction Time",
	Tag(0x9F22): "Certification Authority Public Key Index",
	Tag(0x9F23): "Upper Consecutive Offline Limit",
	Tag(0x9F26): "Application Cryptogram",
	Tag(0x9F27): "Cryptogram Information Data",
	Tag(0x9F2D): "Integrated Circuit Card (ICC) PIN Encipherment Public Key Certificate",
	Tag(0x9F2E): "Integrated Circuit Card (ICC) PIN Encipherment Public Key Exponent",
	Tag(0x9F2F): "Integrated Circuit Card (ICC) PIN Encipherment Public Key Remainder",
	Tag(0x9F32): "Issuer Public Key Exponent",
	Tag(0x9F33): "Terminal Capabilities",
	Tag(0x9F34): "Cardholder Verification Method (CVM) Results",
	Tag(0x9F35): "Terminal Type",
	Tag(0x9F36): "Application Transaction Counter (ATC)",
	Tag(0x9F37): "Unpredictable Number",
	Tag(0x9F38): "Processing Options Data Object List (PDOL)",
	Tag(0x9F39): "Point-of-Service (POS) Entry Mode",
	Tag(0x9F3A): "Amount, Reference Currency",
	Tag(0x9F3B): "Application Reference Currency",
	Tag(0x9F3C): "Transaction Reference Currency Code",
	Tag(0x9F3D): "Transaction Reference Currency Exponent",
	Tag(0x9F40): "Additional Terminal Capabilities",
	Tag(0x9F41): "Transaction Sequence Counter",
	Tag(0x9F42): "Application Currency Code",
	Tag(0x9F43): "Application Reference Currency Exponent",
	Tag(0x9F44): "Application Currency Exponent",
	Tag(0x9F45): "Data Authentication Code",
	Tag(0x9F46): "Integrated Circuit Card (ICC) Public Key Certificate",
	Tag(0x9F47): "Integrated Circuit Card (ICC) Public Key Exponent",
	Tag(0x9F48): "Integrated Circuit Card (ICC) Public Key Remainder",
	Tag(0x9F49): "Dynamic Data Authentication Data Object List (DDOL)",
	Tag(0x9F4A): "Static Data Authentication Tag List",
	Tag(0x9F4B): "Signed Dynamic Application Data",
	Tag(0x9F4C): "ICC Dynamic Number",
	Tag(0x9F4D): "Log Entry",
	Tag(0x9F4E): "Merchant Name and Location",
	Tag(0x9F4F): "Log Format",
	Tag(0xA5):   "File Control Information (FCI) Proprietary Template",
	Tag(0xBF0C): "File Control Information (FCI) Issuer Discretionary Data",
}

func (t Tag) NameOrDefault(def string) string {
	if name, ok := tagNames[t]; ok {
		return name
	}
	return def
}

var tagDescriptions = map[Tag]string{
	Tag(0x42):   "The number that identifies the major industry and the card issuer and that forms the first part of the Primary Account Number (PAN)",
	Tag(0x4F):   "Identifies the application as described in ISO/IEC 7816-5",
	Tag(0x50):   "Mnemonic associated with the AID according to ISO/IEC 7816-5",
	Tag(0x57):   "Contains the data elements of track 2 according to ISO/IEC 7813, excluding start sentinel, end sentinel, and Longitudinal Redundancy Check (LRC), as follows: Primary Account Number (n, var. up to 19) Field Separator (Hex 'D') (b) Expiration Date (YYMM) (n 4) Service Code (n 3) Discretionary Data (defined by individual payment systems) (n, var.) Pad with one Hex 'F' if needed to ensure whole bytes (b)",
	Tag(0x5A):   "Valid cardholder account number",
	Tag(0x5F20): "Indicates cardholder name according to ISO 7813",
	Tag(0x5F24): "Date after which application expires",
	Tag(0x5F25): "Date from which the application may be used",
	Tag(0x5F28): "Indicates the country of the issuer according to ISO 3166",
	Tag(0x5F2A): "Indicates the currency code of the transaction according to ISO 4217",
	Tag(0x5F2D): "1–4 languages stored in order of preference, each represented by 2 alphabetical characters according to ISO 639 Note: EMVCo strongly recommends that cards be personalised with data element '5F2D' coded in lowercase, but that terminals accept the data element whether it is coded in upper or lower case.",
	Tag(0x5F30): "Service code as defined in ISO/IEC 7813 for track 1 and track 2",
	Tag(0x5F34): "Identifies and differentiates cards with the same PAN",
	Tag(0x5F36): "Indicates the implied position of the decimal point from the right of the transaction amount represented according to ISO 4217",
	Tag(0x5F50): "The URL provides the location of the Issuer’s Library Server on the Internet.",
	Tag(0x5F53): "Uniquely identifies the account of a customer at a financial institution as defined in ISO 13616.",
	Tag(0x5F54): "Uniquely identifies a bank as defined in ISO 9362.",
	Tag(0x5F55): "Indicates the country of the issuer as defined in ISO 3166 (using a 2 character alphabetic code)",
	Tag(0x5F56): "Indicates the country of the issuer as defined in ISO 3166 (using a 3 character alphabetic code)",
	Tag(0x61):   "Contains one or more data objects relevant to an application directory entry according to ISO/IEC 7816-5",
	Tag(0x6F):   "Identifies the FCI template according to ISO/IEC 7816-4",
	Tag(0x70):   "Template proprietary to the EMV specification",
	Tag(0x71):   "Contains proprietary issuer data for transmission to the ICC before the second GENERATE AC command",
	Tag(0x72):   "Contains proprietary issuer data for transmission to the ICC after the second GENERATE AC command",
	Tag(0x73):   "Issuer discretionary part of the directory according to ISO/IEC 7816-5",
	Tag(0x77):   "Contains the data objects (with tags and lengths) returned by the ICC in response to a command",
	Tag(0x80):   "Contains the data objects (without tags and lengths) returned by the ICC in response to a command",
	Tag(0x81):   "Authorised amount of the transaction (excluding adjustments)",
	Tag(0x82):   "Indicates the capabilities of the card to support specific functions in the application",
	Tag(0x83):   "Identifies the data field of a command message",
	Tag(0x84):   "Identifies the name of the DF as described in ISO/IEC 7816-4",
	Tag(0x86):   "Contains a command for transmission to the ICC",
	Tag(0x87):   "Indicates the priority of a given application or group of applications in a directory",
	Tag(0x88):   "Identifies the SFI to be used in the commands related to a given AEF or DDF. The SFI data object is a binary field with the three high order bits set to zero.",
	Tag(0x89):   "Value generated by the authorisation authority for an approved transaction",
	Tag(0x8A):   "Code that defines the disposition of a message",
	Tag(0x8C):   "List of data objects (tag and length) to be passed to the ICC in the first GENERATE AC command",
	Tag(0x8D):   "List of data objects (tag and length) to be passed to the ICC in the second GENERATE AC command",
	Tag(0x8E):   "Identifies a method of verification of the cardholder supported by the application",
	Tag(0x8F):   "Identifies the certification authority’s public key in conjunction with the RID",
	Tag(0x90):   "Issuer public key certified by a certification authority",
	Tag(0x91):   "Data sent to the ICC for online issuer authentication",
	Tag(0x92):   "Remaining digits of the Issuer Public Key Modulus",
	Tag(0x93):   "Digital signature on critical application parameters for SDA",
	Tag(0x94):   "Indicates the location (SFI, range of records) of the AEFs related to a given application",
	Tag(0x95):   "Status of the different functions as seen from the terminal",
	Tag(0x97):   "List of data objects (tag and length) to be used by the terminal in generating the TC Hash Value",
	Tag(0x98):   "Result of a hash function specified in Book 2, Annex B3.1",
	Tag(0x99):   "Data entered by the cardholder for the purpose of the PIN verification",
	Tag(0x9A):   "Local date that the transaction was authorised",
	Tag(0x9B):   "Indicates the functions performed in a transaction",
	Tag(0x9C):   "Indicates the type of financial transaction, represented by the first two digits of ISO 8583:1987 Processing Code",
	Tag(0x9D):   "Identifies the name of a DF associated with a directory",
	Tag(0x9F01): "Uniquely identifies the acquirer within each payment system",
	Tag(0x9F02): "Authorised amount of the transaction (excluding adjustments)",
	Tag(0x9F03): "Secondary amount associated with the transaction representing a cashback amount",
	Tag(0x9F04): "Secondary amount associated with the transaction representing a cashback amount",
	Tag(0x9F05): "Issuer or payment system specified data relating to the application",
	Tag(0x9F06): "Identifies the application as described in ISO/IEC 7816-5",
	Tag(0x9F07): "Indicates issuer’s specified restrictions on the geographic usage and services allowed for the application",
	Tag(0x9F08): "Version number assigned by the payment system for the application",
	Tag(0x9F09): "Version number assigned by the payment system for the application",
	Tag(0x9F0B): "Indicates the whole cardholder name when greater than 26 characters using the same coding convention as in ISO 7813",
	Tag(0x9F0D): "Specifies the issuer’s conditions that cause a transaction to be rejected if it might have been approved online, but the terminal is unable to process the transaction online",
	Tag(0x9F0E): "Specifies the issuer’s conditions that cause the denial of a transaction without attempt to go online",
	Tag(0x9F0F): "Specifies the issuer’s conditions that cause a transaction to be transmitted online",
	Tag(0x9F10): "Contains proprietary application data for transmission to the issuer in an online transaction",
	Tag(0x9F11): "Indicates the code table according to ISO/IEC 8859 for displaying the Application Preferred Name",
	Tag(0x9F12): "Preferred mnemonic associated with the AID",
	Tag(0x9F13): "ATC value of the last transaction that went online",
	Tag(0x9F14): "Issuer-specified preference for the maximum number of consecutive offline transactions for this ICC application allowed in a terminal with online capability",
	Tag(0x9F15): "Classifies the type of business being done by the merchant, represented according to ISO 8583:1993 for Card Acceptor Business Code",
	Tag(0x9F16): "When concatenated with the Acquirer Identifier, uniquely identifies a given merchant",
	Tag(0x9F17): "Number of PIN tries remaining",
	Tag(0x9F18): "Identification of the Issuer Script",
	Tag(0x9F1A): "Indicates the country of the terminal, represented according to ISO 3166",
	Tag(0x9F1B): "Indicates the floor limit in the terminal in conjunction with the AID",
	Tag(0x9F1C): "Designates the unique location of a terminal at a merchant",
	Tag(0x9F1D): "Application-specific value used by the card for risk management purposes",
	Tag(0x9F1E): "Unique and permanent serial number assigned to the IFD by the manufacturer",
	Tag(0x9F1F): "Discretionary part of track 1 according to ISO/IEC 7813",
	Tag(0x9F20): "Discretionary part of track 2 according to ISO/IEC 7813",
	Tag(0x9F21): "Local time that the transaction was authorised",
	Tag(0x9F22): "Identifies the certification authority’s public key in conjunction with the RID",
	Tag(0x9F23): "Issuer-specified preference for the maximum number of consecutive offline transactions for this ICC application allowed in a terminal without online capability",
	Tag(0x9F26): "Cryptogram returned by the ICC in response of the GENERATE AC command",
	Tag(0x9F27): "Indicates the type of cryptogram and the actions to be performed by the terminal",
	Tag(0x9F2D): "ICC PIN Encipherment Public Key certified by the issuer",
	Tag(0x9F2E): "ICC PIN Encipherment Public Key Exponent used for PIN encipherment",
	Tag(0x9F2F): "Remaining digits of the ICC PIN Encipherment Public Key Modulus",
	Tag(0x9F32): "Issuer public key exponent used for theverification of the Signed Static Application Data and the ICC Public Key Certificate",
	Tag(0x9F33): "Indicates the card data input, CVM, and security capabilities of the terminal",
	Tag(0x9F34): "Indicates the results of the last CVM performed",
	Tag(0x9F35): "Indicates the environment of the terminal, its communications capability, and its operational control",
	Tag(0x9F36): "Counter maintained by the application in the ICC (incrementing the ATC is managed by the ICC)",
	Tag(0x9F37): "Value to provide variability and uniqueness to the generation of a cryptogram",
	Tag(0x9F38): "Contains a list of terminal resident data objects (tags and lengths) needed by the ICC in processing the GET PROCESSING OPTIONS command",
	Tag(0x9F39): "Indicates the method by which the PAN was entered, according to the first two digits of the ISO 8583:1987 POS Entry Mode",
	Tag(0x9F3A): "Authorised amount expressed in the reference currency",
	Tag(0x9F3B): "1–4 currency codes used between the terminal and the ICC when the Transaction Currency Code is different from the Application Currency Code; each code is 3 digits according to ISO 4217",
	Tag(0x9F3C): "Code defining the common currency used by the terminal in case the Transaction Currency Code is different from the Application Currency Code",
	Tag(0x9F3D): "Indicates the implied position of the decimal point from the right of the transaction amount, with the Transaction Reference Currency Code represented according to ISO 4217",
	Tag(0x9F40): "Indicates the data input and output capabilities of the terminal",
	Tag(0x9F41): "Counter maintained by the terminal that is incremented by one for each transaction",
	Tag(0x9F42): "Indicates the currency in which the account is managed according to ISO 4217",
	Tag(0x9F43): "Indicates the implied position of the decimal point from the right of the amount, for each of the 1–4 reference currencies represented according to ISO 4217",
	Tag(0x9F44): "Indicates the implied position of the decimal point from the right of the amount represented according to ISO 4217",
	Tag(0x9F45): "An issuer assigned value that is retained by the terminal during the verification process of the Signed Static Application Data",
	Tag(0x9F46): "ICC Public Key certified by the issuer",
	Tag(0x9F47): "ICC Public Key Exponent used for the verification of the Signed Dynamic Application Data",
	Tag(0x9F48): "Remaining digits of the ICC Public Key Modulus",
	Tag(0x9F49): "List of data objects (tag and length) to be passed to the ICC in the INTERNAL AUTHENTICATE command",
	Tag(0x9F4A): "List of tags of primitive data objects defined in this specification whose value fields are to be included in the Signed Static or Dynamic Application Data",
	Tag(0x9F4B): "Digital signature on critical application parameters for DDA or CDA",
	Tag(0x9F4C): "Time-variant number generated by the ICC, to be captured by the terminal",
	Tag(0x9F4D): "Provides the SFI of the Transaction Log file and its number of records",
	Tag(0x9F4E): "Indicates the name and location of the merchant",
	Tag(0x9F4F): "List (in tag and length format) of data objects representing the logged data elements that are passed to the terminal when a transaction log record is read",
	Tag(0xA5):   "Identifies the data object proprietary to this specification in the FCI template according to ISO/IEC 7816-4",
	Tag(0xBF0C): "Issuer discretionary part of the FCI",
}

func (t Tag) DescriptionOrDefault(def string) string {
	if name, ok := tagDescriptions[t]; ok {
		return name
	}
	return def
}

const (
	Tag42_IssuerIdentificationNumberIIN                        Tag = 0x42
	Tag4F_ApplicationID                                        Tag = 0x4F
	Tag50_ApplicationLabel                                     Tag = 0x50
	Tag57_Track2EquivalentData                                 Tag = 0x57
	Tag5A_ApplicationPAN                                       Tag = 0x5A
	Tag5F20_CardholderName                                     Tag = 0x5F20
	Tag5F24_ApplicationExpirationDate                          Tag = 0x5F24
	Tag5F25_ApplicationEffectiveDate                           Tag = 0x5F25
	Tag5F28_IssuerCountryCode                                  Tag = 0x5F28
	Tag5F2A_TransactionCurrencyCode                            Tag = 0x5F2A
	Tag5F2D_LanguagePreference                                 Tag = 0x5F2D
	Tag5F30_ServiceCode                                        Tag = 0x5F30
	Tag5F34_ApplicationPANSequenceNumber                       Tag = 0x5F34
	Tag5F36_TransactionCurrencyExponent                        Tag = 0x5F36
	Tag5F50_IssuerURL                                          Tag = 0x5F50
	Tag5F53_InternationalBankAccountNumberIBAN                 Tag = 0x5F53
	Tag5F54_BankIdentifierCodeBIC                              Tag = 0x5F54
	Tag5F55_IssuerCountryCodealpha2format                      Tag = 0x5F55
	Tag5F56_IssuerCountryCodealpha3format                      Tag = 0x5F56
	Tag61_ApplicationTemplate                                  Tag = 0x61
	Tag6F_FileControlInformationFCITemplate                    Tag = 0x6F
	Tag70_EMVProprietaryTemplate                               Tag = 0x70
	Tag71_IssuerScriptTemplate1                                Tag = 0x71
	Tag72_IssuerScriptTemplate2                                Tag = 0x72
	Tag73_DirectoryDiscretionaryTemplate                       Tag = 0x73
	Tag77_ResponseMessageTemplateFormat2                       Tag = 0x77
	Tag80_ResponseMessageTemplateFormat1                       Tag = 0x80
	Tag81_AmountAuthorisedBinary                               Tag = 0x81
	Tag82_ApplicationInterchangeProfile                        Tag = 0x82
	Tag83_CommandTemplate                                      Tag = 0x83
	Tag84_DedicatedFileDFName                                  Tag = 0x84
	Tag86_IssuerScriptCommand                                  Tag = 0x86
	Tag87_ApplicationPriorityIndicator                         Tag = 0x87
	Tag88_ShortFileIdentifierSFI                               Tag = 0x88
	Tag89_AuthorisationCode                                    Tag = 0x89
	Tag8A_AuthorisationResponseCode                            Tag = 0x8A
	Tag8C_CDOL1                                                Tag = 0x8C
	Tag8D_CDOL2                                                Tag = 0x8D
	Tag8E_CardholderVerificationMethodList                     Tag = 0x8E
	Tag8F_CAPublicKeyIndex1                                    Tag = 0x8F
	Tag90_IssuerPublicKeyCertificate                           Tag = 0x90
	Tag91_IssuerAuthenticationData                             Tag = 0x91
	Tag92_IssuerPublicKeyRemainder                             Tag = 0x92
	Tag93_SignedStaticApplicationData                          Tag = 0x93
	Tag94_ApplicationFileLocatorAFL                            Tag = 0x94
	Tag95_TerminalVerificationResults                          Tag = 0x95
	Tag97_TransactionCertificateDataObjectListTDOL             Tag = 0x97
	Tag98_TransactionCertificateTCHashValue                    Tag = 0x98
	Tag99_TransactionPersonalIdentificationNumberPINData       Tag = 0x99
	Tag9A_TransactionDate                                      Tag = 0x9A
	Tag9B_TransactionStatusInformation                         Tag = 0x9B
	Tag9C_TransactionType                                      Tag = 0x9C
	Tag9D_DirectoryDefinitionFileDDFName                       Tag = 0x9D
	Tag9F01_AcquirerIdentifier                                 Tag = 0x9F01
	Tag9F02_AmountAuthorisedNumeric                            Tag = 0x9F02
	Tag9F03_AmountOtherNumeric                                 Tag = 0x9F03
	Tag9F04_AmountOtherBinary                                  Tag = 0x9F04
	Tag9F05_ApplicationDiscretionaryData                       Tag = 0x9F05
	Tag9F06_AIDterminal                                        Tag = 0x9F06
	Tag9F07_ApplicationUsageControl                            Tag = 0x9F07
	Tag9F08_ApplicationVersionNumber1                          Tag = 0x9F08
	Tag9F09_ApplicationVersionNumber2                          Tag = 0x9F09
	Tag9F0B_CardholderNameExtended                             Tag = 0x9F0B
	Tag9F0D_IssuerActionCodeDefault                            Tag = 0x9F0D
	Tag9F0E_IssuerActionCodeDenial                             Tag = 0x9F0E
	Tag9F0F_IssuerActionCodeOnline                             Tag = 0x9F0F
	Tag9F10_IssuerApplicationData                              Tag = 0x9F10
	Tag9F11_IssuerCodeTableIndex                               Tag = 0x9F11
	Tag9F12_ApplicationPreferredName                           Tag = 0x9F12
	Tag9F13_LastOnlineApplicationTransactionCounterATCRegister Tag = 0x9F13
	Tag9F14_LowerConsecutiveOfflineLimit                       Tag = 0x9F14
	Tag9F15_MerchantCategoryCode                               Tag = 0x9F15
	Tag9F16_MerchantIdentifier                                 Tag = 0x9F16
	Tag9F17_PersonalIdentificationNumberPINTryCounter          Tag = 0x9F17
	Tag9F18_IssuerScriptIdentifier                             Tag = 0x9F18
	Tag9F1A_TerminalCountryCode                                Tag = 0x9F1A
	Tag9F1B_TerminalFloorLimit                                 Tag = 0x9F1B
	Tag9F1C_TerminalIdentification                             Tag = 0x9F1C
	Tag9F1D_TerminalRiskManagementData                         Tag = 0x9F1D
	Tag9F1E_InterfaceDeviceIFDSerialNumber                     Tag = 0x9F1E
	Tag9F1F_Track1DiscretionaryData                            Tag = 0x9F1F
	Tag9F20_Track2DiscretionaryData                            Tag = 0x9F20
	Tag9F21_TransactionTime                                    Tag = 0x9F21
	Tag9F22_CAPublicKeyIndex2                                  Tag = 0x9F22
	Tag9F23_UpperConsecutiveOfflineLimit                       Tag = 0x9F23
	Tag9F26_ApplicationCryptogram                              Tag = 0x9F26
	Tag9F27_CryptogramInformationData                          Tag = 0x9F27
	Tag9F2D_ICCPINEnciphermentPublicKeyCertificate             Tag = 0x9F2D
	Tag9F2E_ICCPINEnciphermentPublicKeyExponent                Tag = 0x9F2E
	Tag9F2F_ICCPINEnciphermentPublicKeyRemainder               Tag = 0x9F2F
	Tag9F32_IssuerPublicKeyExponent                            Tag = 0x9F32
	Tag9F33_TerminalCapabilities                               Tag = 0x9F33
	Tag9F34_CardholderVerificationMethodResults                Tag = 0x9F34
	Tag9F35_TerminalType                                       Tag = 0x9F35
	Tag9F36_ApplicationTransactionCounter                      Tag = 0x9F36
	Tag9F37_UnpredictableNumber                                Tag = 0x9F37
	Tag9F38_ProcessingOptionsDataObjectListPDOL                Tag = 0x9F38
	Tag9F39_PointOfServicePOSEntryMode                         Tag = 0x9F39
	Tag9F3A_AmountReferenceCurrency                            Tag = 0x9F3A
	Tag9F3B_ApplicationReferenceCurrency                       Tag = 0x9F3B
	Tag9F3C_TransactionReferenceCurrencyCode                   Tag = 0x9F3C
	Tag9F3D_TransactionReferenceCurrencyExponent               Tag = 0x9F3D
	Tag9F40_AdditionalTerminalCapabilities                     Tag = 0x9F40
	Tag9F41_TransactionSequenceCounter                         Tag = 0x9F41
	Tag9F42_ApplicationCurrencyCode                            Tag = 0x9F42
	Tag9F43_ApplicationReferenceCurrencyExponent               Tag = 0x9F43
	Tag9F44_ApplicationCurrencyExponent                        Tag = 0x9F44
	Tag9F45_DataAuthenticationCode                             Tag = 0x9F45
	Tag9F46_ICCPublicKeyCertificate                            Tag = 0x9F46
	Tag9F47_ICCPublicKeyExponent                               Tag = 0x9F47
	Tag9F48_ICCPublicKeyRemainder                              Tag = 0x9F48
	Tag9F49_DynamicDataAuthenticationDataObjectListDDOL        Tag = 0x9F49
	Tag9F4A_StaticDataAuthenticationTagList                    Tag = 0x9F4A
	Tag9F4B_SignedDynamicApplicationData                       Tag = 0x9F4B
	Tag9F4C_ICCDynamicNumber                                   Tag = 0x9F4C
	Tag9F4D_LogEntry                                           Tag = 0x9F4D
	Tag9F4E_MerchantNameandLocation                            Tag = 0x9F4E
	Tag9F4F_LogFormat                                          Tag = 0x9F4F
	TagA5_FileControlInformationFCIProprietaryTemplate         Tag = 0xA5
	TagBF0C_FileControlInformationFCIIssuerDiscretionaryData   Tag = 0xBF0C
)
