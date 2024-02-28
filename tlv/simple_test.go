package tlv

// func TestUnmarshalMap(t *testing.T) {
// 	de55 := tests.MustParseHex(t, "9F02060000000001009F03060000000000009F2608B1B2B3B4B5B6B7B89F0607A0000000000001820255889F0702FF009F2701809F34034433228407B00000000000089F1E0844332211009988779F10080105A000000000009F3303E0F0A09F1A0209919F350199950511229988775F2A0209929A031234569C01009F3704ABCD01239F36020100")

// 	de55map, err := UnmarshalMap(de55)
// 	require.NoError(t, err)
// 	require.NotNil(t, de55map)
// 	require.NotEmpty(t, de55map)

// 	tests.AssertBytesEqual(t, "5588", de55map[Tag(0x82)])
// 	tests.AssertBytesEqual(t, "443322", de55map[Tag(0x9F34)])
// 	tests.AssertBytesEqual(t, "0991", de55map[Tag(0x9F1A)])
// 	tests.AssertBytesEqual(t, "A0000000000001", de55map[Tag(0x9F06)])
// 	tests.AssertBytesEqual(t, "B0000000000008", de55map[Tag(0x84)])
// 	tests.AssertBytesEqual(t, "4433221100998877", de55map[Tag(0x9F1E)])
// 	tests.AssertBytesEqual(t, "E0F0A0", de55map[Tag(0x9F33)])
// 	tests.AssertBytesEqual(t, "000000000100", de55map[Tag(0x9F02)])
// 	tests.AssertBytesEqual(t, "B1B2B3B4B5B6B7B8", de55map[Tag(0x9F26)])
// 	tests.AssertBytesEqual(t, "0105A00000000000", de55map[Tag(0x9F10)])
// 	tests.AssertBytesEqual(t, "99", de55map[Tag(0x9F35)])
// 	tests.AssertBytesEqual(t, "0992", de55map[Tag(0x5F2A)])
// 	tests.AssertBytesEqual(t, "123456", de55map[Tag(0x9A)])
// 	tests.AssertBytesEqual(t, "0100", de55map[Tag(0x9F36)])
// 	tests.AssertBytesEqual(t, "000000000000", de55map[Tag(0x9F03)])
// 	tests.AssertBytesEqual(t, "FF00", de55map[Tag(0x9F07)])
// 	tests.AssertBytesEqual(t, "80", de55map[Tag(0x9F27)])
// 	tests.AssertBytesEqual(t, "1122998877", de55map[Tag(0x95)])
// 	tests.AssertBytesEqual(t, "00", de55map[Tag(0x9C)])
// 	tests.AssertBytesEqual(t, "ABCD0123", de55map[Tag(0x9F37)])
// }
