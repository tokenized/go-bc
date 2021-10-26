package spv

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/libsv/go-bc"
)

func TestEnvelope_IsAnchored(t *testing.T) {
	tests := map[string]struct {
		envelope Envelope
		exp      bool
	}{
		"is anchored": {
			envelope: Envelope{
				Proof: &bc.MerkleProof{},
			},
			exp: true,
		},
		"is not anchored": {
			envelope: Envelope{},
			exp:      false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, test.exp, test.envelope.IsAnchored())
		})
	}
}

func TestEnvelope_Bytes_IsValid(t *testing.T) {
	tests := map[string]struct {
		jsonString string
		hexString  string
	}{
		"simple": {
			jsonString: `{
				"txid": "d23ac12a990c3be3ff53bac731a5e9839375854dbfd889e420f05abf05204ecc",
				"rawTx": "0100000001f49f4b06f4f3244323fd11e7931838308780eafca389cd32b8ff614056088cfb010000006a4730440220470ec034c9f5a41fa5ebb752c1d7bfad5af7659861c52aae87768a6289bf110602207d584a686235800e9624b9ceeb9704b927c005b32310810987ec01652196ab7741210305d46481dd94e548669d30689e3b57d0a497e7265786308e3c6809dd8cee5dadffffffff02a00f0000000000001976a9147274c98d89bddefa863157f5a0f4789bc85856ac88ac81790000000000001976a914b77edad7bf765b4f1c412c49d9e7e549db98d6c988ac00000000",
				"parents": {
					"fb8c08564061ffb832cd89a3fcea808730381893e711fd234324f3f4064b9ff4": {
						"txid": "fb8c08564061ffb832cd89a3fcea808730381893e711fd234324f3f4064b9ff4",
						"rawTx": "0100000001c85091ec57f85d5cbb33a0926ff1bce469336f1912aaf73cd3977ff019e692de000000006b483045022100f2204fd3d87cab883c9d8d38068526eb653632c226c658480f72c1991c47f7e702207d2a20e6c477fe066b2a5976f1869006f21e34abdfa3fdf969c188e4b340f8d2412103d46926f6022e11ae35377a0277dc30bf0ed89282751301d0bd7720b590f9a1dbffffffff02a00f0000000000001976a91495cb3f890282d0aef458b9ca7d4a8f1b69c186b988ac92890000000000001976a9141c4f1e75d42057361e5d9443115c1938508f6e6388ac00000000",
						"parents": {
							"de92e619f07f97d33cf7aa12196f3369e4bcf16f92a033bb5c5df857ec9150c8": {
								"txid": "de92e619f07f97d33cf7aa12196f3369e4bcf16f92a033bb5c5df857ec9150c8",
								"rawTx": "0100000001f5668131b454c6d1960abc0cbf1be7fa938b0159560aa8cf9b9ce0def11898cd000000006b483045022100db3438332eec734c2393af37dfbd1c6ee1d00a5758c03a898a9cc3d3716f0798022077d1bdca0408651ab704feac5b9f1360d57db4819139d0518faf0eb4e48d1922412103ab3a2cf940e5f0aa0aa2bdd81c7ccc254de9d00dd677cc30e7486530ed9be092ffffffff01a3990000000000001976a914689547124e697984194a62f4c70506e7240962e688ac00000000",
								"proof": {
									"index": 2,
									"txOrId": "de92e619f07f97d33cf7aa12196f3369e4bcf16f92a033bb5c5df857ec9150c8",
									"target": "00000020d334108eb95ddefc0ea5ffbfc4ae7792cf5ed54bac9f80608d26d79c00000000f5b42d19624ac642ba93d0443c8296c742d1f0dd509878c1b1c9f71d1b4c9b102ac868616aa3001d04557ccd",
									"nodes": [
										"4c05bd4c079a2269f14a4347e959abaccb37697f70cbb08b8426e6674e09cd24",
										"374c06c4ee471a2687498bd09bf42322aea3ca1e653cd23810baa1609b0ce25e",
										"f4e18eb36ecde0719e1c8a2dc803768af250d76d08f4ab1a9fd2c08d905b6af3"
									],
									"targetType": "header"
								}
							}
						}
					}
				}
			}`,
			hexString: "0101e10100000001f49f4b06f4f3244323fd11e7931838308780eafca389cd32b8ff614056088cfb010000006a4730440220470ec034c9f5a41fa5ebb752c1d7bfad5af7659861c52aae87768a6289bf110602207d584a686235800e9624b9ceeb9704b927c005b32310810987ec01652196ab7741210305d46481dd94e548669d30689e3b57d0a497e7265786308e3c6809dd8cee5dadffffffff02a00f0000000000001976a9147274c98d89bddefa863157f5a0f4789bc85856ac88ac81790000000000001976a914b77edad7bf765b4f1c412c49d9e7e549db98d6c988ac0000000001e20100000001c85091ec57f85d5cbb33a0926ff1bce469336f1912aaf73cd3977ff019e692de000000006b483045022100f2204fd3d87cab883c9d8d38068526eb653632c226c658480f72c1991c47f7e702207d2a20e6c477fe066b2a5976f1869006f21e34abdfa3fdf969c188e4b340f8d2412103d46926f6022e11ae35377a0277dc30bf0ed89282751301d0bd7720b590f9a1dbffffffff02a00f0000000000001976a91495cb3f890282d0aef458b9ca7d4a8f1b69c186b988ac92890000000000001976a9141c4f1e75d42057361e5d9443115c1938508f6e6388ac0000000001c00100000001f5668131b454c6d1960abc0cbf1be7fa938b0159560aa8cf9b9ce0def11898cd000000006b483045022100db3438332eec734c2393af37dfbd1c6ee1d00a5758c03a898a9cc3d3716f0798022077d1bdca0408651ab704feac5b9f1360d57db4819139d0518faf0eb4e48d1922412103ab3a2cf940e5f0aa0aa2bdd81c7ccc254de9d00dd677cc30e7486530ed9be092ffffffff01a3990000000000001976a914689547124e697984194a62f4c70506e7240962e688ac0000000002d60202c85091ec57f85d5cbb33a0926ff1bce469336f1912aaf73cd3977ff019e692decd7c55041d00a36a6168c82a109b4c1b1df7c9b1c1789850ddf0d142c796823c44d093ba42c64a62192db4f5000000009cd7268d60809fac4bd55ecf9277aec4bfffa50efcde5db98e1034d320000000030024cd094e67e626848bb0cb707f6937cbacab59e947434af169229a074cbd054c005ee20c9b60a1ba1038d23c651ecaa3ae2223f49bd08b4987261a47eec4064c3700f36a5b908dc0d29f1aabf4086dd750f28a7603c82d8a1c9e71e0cd6eb38ee1f4",
		},
		"extra parents": {
			jsonString: `{
				"txid": "d23ac12a990c3be3ff53bac731a5e9839375854dbfd889e420f05abf05204ecc",
				"rawTx": "0100000001f49f4b06f4f3244323fd11e7931838308780eafca389cd32b8ff614056088cfb010000006a4730440220470ec034c9f5a41fa5ebb752c1d7bfad5af7659861c52aae87768a6289bf110602207d584a686235800e9624b9ceeb9704b927c005b32310810987ec01652196ab7741210305d46481dd94e548669d30689e3b57d0a497e7265786308e3c6809dd8cee5dadffffffff02a00f0000000000001976a9147274c98d89bddefa863157f5a0f4789bc85856ac88ac81790000000000001976a914b77edad7bf765b4f1c412c49d9e7e549db98d6c988ac00000000",
				"parents": {
					"fb8c08564061ffb832cd89a3fcea808730381893e711fd234324f3f4064b9ff4": {
						"txid": "fb8c08564061ffb832cd89a3fcea808730381893e711fd234324f3f4064b9ff4",
						"rawTx": "0100000001c85091ec57f85d5cbb33a0926ff1bce469336f1912aaf73cd3977ff019e692de000000006b483045022100f2204fd3d87cab883c9d8d38068526eb653632c226c658480f72c1991c47f7e702207d2a20e6c477fe066b2a5976f1869006f21e34abdfa3fdf969c188e4b340f8d2412103d46926f6022e11ae35377a0277dc30bf0ed89282751301d0bd7720b590f9a1dbffffffff02a00f0000000000001976a91495cb3f890282d0aef458b9ca7d4a8f1b69c186b988ac92890000000000001976a9141c4f1e75d42057361e5d9443115c1938508f6e6388ac00000000",
						"parents": {
							"de92e619f07f97d33cf7aa12196f3369e4bcf16f92a033bb5c5df857ec9150c8": {
								"txid": "de92e619f07f97d33cf7aa12196f3369e4bcf16f92a033bb5c5df857ec9150c8",
								"rawTx": "0100000001f5668131b454c6d1960abc0cbf1be7fa938b0159560aa8cf9b9ce0def11898cd000000006b483045022100db3438332eec734c2393af37dfbd1c6ee1d00a5758c03a898a9cc3d3716f0798022077d1bdca0408651ab704feac5b9f1360d57db4819139d0518faf0eb4e48d1922412103ab3a2cf940e5f0aa0aa2bdd81c7ccc254de9d00dd677cc30e7486530ed9be092ffffffff01a3990000000000001976a914689547124e697984194a62f4c70506e7240962e688ac00000000",
								"proof": {
									"index": 2,
									"txOrId": "de92e619f07f97d33cf7aa12196f3369e4bcf16f92a033bb5c5df857ec9150c8",
									"target": "00000020d334108eb95ddefc0ea5ffbfc4ae7792cf5ed54bac9f80608d26d79c00000000f5b42d19624ac642ba93d0443c8296c742d1f0dd509878c1b1c9f71d1b4c9b102ac868616aa3001d04557ccd",
									"nodes": [
										"4c05bd4c079a2269f14a4347e959abaccb37697f70cbb08b8426e6674e09cd24",
										"374c06c4ee471a2687498bd09bf42322aea3ca1e653cd23810baa1609b0ce25e",
										"f4e18eb36ecde0719e1c8a2dc803768af250d76d08f4ab1a9fd2c08d905b6af3"
									],
									"targetType": "header"
								},
								"parents": {
									"cd9818f1dee09c9bcfa80a5659018b93fae71bbf0cbc0a96d1c654b4318166f5": {
										"txid": "cd9818f1dee09c9bcfa80a5659018b93fae71bbf0cbc0a96d1c654b4318166f5",
										"rawTx": "0200000001b77ec0a9c31242ab9ab0c26b62eb72f7270408ab158b25487d262c47ffd0ed8a020000006b483045022100c473129b95c26dc5f43a42516f750efa8f0fa3173de102fa3d782d4605740c9e0220029da8e1f7651f10302a9bd492c401fc84f88c6444d264b1ce45ec42eae86b574121032097ea81a1d7211b1c6e25a6cc10723a716c63bbbda6f9fe74095a3ed6398a27ffffffff03399a0000000000001976a914e77f11b17677510e4e21f8e0b298119f3bdf0a5b88acdc430000000000001976a914510052b5a1ab59a18ccaee53ab53477c6750f36188acc49c5921000000001976a914c1120654de9e85005befb76b39e90fb7231e107888ac00000000",
										"proof": {
											"index": 2,
											"txOrId": "cd9818f1dee09c9bcfa80a5659018b93fae71bbf0cbc0a96d1c654b4318166f5",
											"target": "00000020d334108eb95ddefc0ea5ffbfc4ae7792cf5ed54bac9f80608d26d79c00000000f5b42d19624ac642ba93d0443c8296c742d1f0dd509878c1b1c9f71d1b4c9b102ac868616aa3001d04557ccd",
											"nodes": [
												"4c05bd4c079a2269f14a4347e959abaccb37697f70cbb08b8426e6674e09cd24",
												"374c06c4ee471a2687498bd09bf42322aea3ca1e653cd23810baa1609b0ce25e",
												"f4e18eb36ecde0719e1c8a2dc803768af250d76d08f4ab1a9fd2c08d905b6af3"
											],
											"targetType": "header"
										}
									}
								}
							}
						}
					}
				}
			}`,
			hexString: "0101e10100000001f49f4b06f4f3244323fd11e7931838308780eafca389cd32b8ff614056088cfb010000006a4730440220470ec034c9f5a41fa5ebb752c1d7bfad5af7659861c52aae87768a6289bf110602207d584a686235800e9624b9ceeb9704b927c005b32310810987ec01652196ab7741210305d46481dd94e548669d30689e3b57d0a497e7265786308e3c6809dd8cee5dadffffffff02a00f0000000000001976a9147274c98d89bddefa863157f5a0f4789bc85856ac88ac81790000000000001976a914b77edad7bf765b4f1c412c49d9e7e549db98d6c988ac0000000001e20100000001c85091ec57f85d5cbb33a0926ff1bce469336f1912aaf73cd3977ff019e692de000000006b483045022100f2204fd3d87cab883c9d8d38068526eb653632c226c658480f72c1991c47f7e702207d2a20e6c477fe066b2a5976f1869006f21e34abdfa3fdf969c188e4b340f8d2412103d46926f6022e11ae35377a0277dc30bf0ed89282751301d0bd7720b590f9a1dbffffffff02a00f0000000000001976a91495cb3f890282d0aef458b9ca7d4a8f1b69c186b988ac92890000000000001976a9141c4f1e75d42057361e5d9443115c1938508f6e6388ac0000000001c00100000001f5668131b454c6d1960abc0cbf1be7fa938b0159560aa8cf9b9ce0def11898cd000000006b483045022100db3438332eec734c2393af37dfbd1c6ee1d00a5758c03a898a9cc3d3716f0798022077d1bdca0408651ab704feac5b9f1360d57db4819139d0518faf0eb4e48d1922412103ab3a2cf940e5f0aa0aa2bdd81c7ccc254de9d00dd677cc30e7486530ed9be092ffffffff01a3990000000000001976a914689547124e697984194a62f4c70506e7240962e688ac0000000002d60202c85091ec57f85d5cbb33a0926ff1bce469336f1912aaf73cd3977ff019e692decd7c55041d00a36a6168c82a109b4c1b1df7c9b1c1789850ddf0d142c796823c44d093ba42c64a62192db4f5000000009cd7268d60809fac4bd55ecf9277aec4bfffa50efcde5db98e1034d320000000030024cd094e67e626848bb0cb707f6937cbacab59e947434af169229a074cbd054c005ee20c9b60a1ba1038d23c651ecaa3ae2223f49bd08b4987261a47eec4064c3700f36a5b908dc0d29f1aabf4086dd750f28a7603c82d8a1c9e71e0cd6eb38ee1f4",
		},
		"no optionals": {
			jsonString: `{
				"rawTx": "0100000001f49f4b06f4f3244323fd11e7931838308780eafca389cd32b8ff614056088cfb010000006a4730440220470ec034c9f5a41fa5ebb752c1d7bfad5af7659861c52aae87768a6289bf110602207d584a686235800e9624b9ceeb9704b927c005b32310810987ec01652196ab7741210305d46481dd94e548669d30689e3b57d0a497e7265786308e3c6809dd8cee5dadffffffff02a00f0000000000001976a9147274c98d89bddefa863157f5a0f4789bc85856ac88ac81790000000000001976a914b77edad7bf765b4f1c412c49d9e7e549db98d6c988ac00000000",
				"parents": {
					"fb8c08564061ffb832cd89a3fcea808730381893e711fd234324f3f4064b9ff4": {
						"rawTx": "0100000001c85091ec57f85d5cbb33a0926ff1bce469336f1912aaf73cd3977ff019e692de000000006b483045022100f2204fd3d87cab883c9d8d38068526eb653632c226c658480f72c1991c47f7e702207d2a20e6c477fe066b2a5976f1869006f21e34abdfa3fdf969c188e4b340f8d2412103d46926f6022e11ae35377a0277dc30bf0ed89282751301d0bd7720b590f9a1dbffffffff02a00f0000000000001976a91495cb3f890282d0aef458b9ca7d4a8f1b69c186b988ac92890000000000001976a9141c4f1e75d42057361e5d9443115c1938508f6e6388ac00000000",
						"parents": {
							"de92e619f07f97d33cf7aa12196f3369e4bcf16f92a033bb5c5df857ec9150c8": {
								"rawTx": "0100000001f5668131b454c6d1960abc0cbf1be7fa938b0159560aa8cf9b9ce0def11898cd000000006b483045022100db3438332eec734c2393af37dfbd1c6ee1d00a5758c03a898a9cc3d3716f0798022077d1bdca0408651ab704feac5b9f1360d57db4819139d0518faf0eb4e48d1922412103ab3a2cf940e5f0aa0aa2bdd81c7ccc254de9d00dd677cc30e7486530ed9be092ffffffff01a3990000000000001976a914689547124e697984194a62f4c70506e7240962e688ac00000000",
								"proof": {
									"index": 2,
									"txOrId": "de92e619f07f97d33cf7aa12196f3369e4bcf16f92a033bb5c5df857ec9150c8",
									"target": "00000020d334108eb95ddefc0ea5ffbfc4ae7792cf5ed54bac9f80608d26d79c00000000f5b42d19624ac642ba93d0443c8296c742d1f0dd509878c1b1c9f71d1b4c9b102ac868616aa3001d04557ccd",
									"nodes": [
										"4c05bd4c079a2269f14a4347e959abaccb37697f70cbb08b8426e6674e09cd24",
										"374c06c4ee471a2687498bd09bf42322aea3ca1e653cd23810baa1609b0ce25e",
										"f4e18eb36ecde0719e1c8a2dc803768af250d76d08f4ab1a9fd2c08d905b6af3"
									],
									"targetType": "header"
								}
							}
						}
					}
				}
			}`,
			hexString: "0101e10100000001f49f4b06f4f3244323fd11e7931838308780eafca389cd32b8ff614056088cfb010000006a4730440220470ec034c9f5a41fa5ebb752c1d7bfad5af7659861c52aae87768a6289bf110602207d584a686235800e9624b9ceeb9704b927c005b32310810987ec01652196ab7741210305d46481dd94e548669d30689e3b57d0a497e7265786308e3c6809dd8cee5dadffffffff02a00f0000000000001976a9147274c98d89bddefa863157f5a0f4789bc85856ac88ac81790000000000001976a914b77edad7bf765b4f1c412c49d9e7e549db98d6c988ac0000000001e20100000001c85091ec57f85d5cbb33a0926ff1bce469336f1912aaf73cd3977ff019e692de000000006b483045022100f2204fd3d87cab883c9d8d38068526eb653632c226c658480f72c1991c47f7e702207d2a20e6c477fe066b2a5976f1869006f21e34abdfa3fdf969c188e4b340f8d2412103d46926f6022e11ae35377a0277dc30bf0ed89282751301d0bd7720b590f9a1dbffffffff02a00f0000000000001976a91495cb3f890282d0aef458b9ca7d4a8f1b69c186b988ac92890000000000001976a9141c4f1e75d42057361e5d9443115c1938508f6e6388ac0000000001c00100000001f5668131b454c6d1960abc0cbf1be7fa938b0159560aa8cf9b9ce0def11898cd000000006b483045022100db3438332eec734c2393af37dfbd1c6ee1d00a5758c03a898a9cc3d3716f0798022077d1bdca0408651ab704feac5b9f1360d57db4819139d0518faf0eb4e48d1922412103ab3a2cf940e5f0aa0aa2bdd81c7ccc254de9d00dd677cc30e7486530ed9be092ffffffff01a3990000000000001976a914689547124e697984194a62f4c70506e7240962e688ac0000000002d60202c85091ec57f85d5cbb33a0926ff1bce469336f1912aaf73cd3977ff019e692decd7c55041d00a36a6168c82a109b4c1b1df7c9b1c1789850ddf0d142c796823c44d093ba42c64a62192db4f5000000009cd7268d60809fac4bd55ecf9277aec4bfffa50efcde5db98e1034d320000000030024cd094e67e626848bb0cb707f6937cbacab59e947434af169229a074cbd054c005ee20c9b60a1ba1038d23c651ecaa3ae2223f49bd08b4987261a47eec4064c3700f36a5b908dc0d29f1aabf4086dd750f28a7603c82d8a1c9e71e0cd6eb38ee1f4",
		},
		"large": {
			jsonString: `{
				"txid": "d23ac12a990c3be3ff53bac731a5e9839375854dbfd889e420f05abf05204ecc",
				"rawTx": "0100000001f49f4b06f4f3244323fd11e7931838308780eafca389cd32b8ff614056088cfb010000006a4730440220470ec034c9f5a41fa5ebb752c1d7bfad5af7659861c52aae87768a6289bf110602207d584a686235800e9624b9ceeb9704b927c005b32310810987ec01652196ab7741210305d46481dd94e548669d30689e3b57d0a497e7265786308e3c6809dd8cee5dadffffffff02a00f0000000000001976a9147274c98d89bddefa863157f5a0f4789bc85856ac88ac81790000000000001976a914b77edad7bf765b4f1c412c49d9e7e549db98d6c988ac00000000",
				"parents": {
					"fb8c08564061ffb832cd89a3fcea808730381893e711fd234324f3f4064b9ff4": {
						"txid": "fb8c08564061ffb832cd89a3fcea808730381893e711fd234324f3f4064b9ff4",
						"rawTx": "0100000001c85091ec57f85d5cbb33a0926ff1bce469336f1912aaf73cd3977ff019e692de000000006b483045022100f2204fd3d87cab883c9d8d38068526eb653632c226c658480f72c1991c47f7e702207d2a20e6c477fe066b2a5976f1869006f21e34abdfa3fdf969c188e4b340f8d2412103d46926f6022e11ae35377a0277dc30bf0ed89282751301d0bd7720b590f9a1dbffffffff02a00f0000000000001976a91495cb3f890282d0aef458b9ca7d4a8f1b69c186b988ac92890000000000001976a9141c4f1e75d42057361e5d9443115c1938508f6e6388ac00000000",
						"parents": {
							"de92e619f07f97d33cf7aa12196f3369e4bcf16f92a033bb5c5df857ec9150c8": {
								"txid": "de92e619f07f97d33cf7aa12196f3369e4bcf16f92a033bb5c5df857ec9150c8",
								"rawTx": "0100000001f5668131b454c6d1960abc0cbf1be7fa938b0159560aa8cf9b9ce0def11898cd000000006b483045022100db3438332eec734c2393af37dfbd1c6ee1d00a5758c03a898a9cc3d3716f0798022077d1bdca0408651ab704feac5b9f1360d57db4819139d0518faf0eb4e48d1922412103ab3a2cf940e5f0aa0aa2bdd81c7ccc254de9d00dd677cc30e7486530ed9be092ffffffff01a3990000000000001976a914689547124e697984194a62f4c70506e7240962e688ac00000000",
								"parents": {
									"cd9818f1dee09c9bcfa80a5659018b93fae71bbf0cbc0a96d1c654b4318166f5": {
										"txid": "cd9818f1dee09c9bcfa80a5659018b93fae71bbf0cbc0a96d1c654b4318166f5",
										"rawTx": "0200000001b77ec0a9c31242ab9ab0c26b62eb72f7270408ab158b25487d262c47ffd0ed8a020000006b483045022100c473129b95c26dc5f43a42516f750efa8f0fa3173de102fa3d782d4605740c9e0220029da8e1f7651f10302a9bd492c401fc84f88c6444d264b1ce45ec42eae86b574121032097ea81a1d7211b1c6e25a6cc10723a716c63bbbda6f9fe74095a3ed6398a27ffffffff03399a0000000000001976a914e77f11b17677510e4e21f8e0b298119f3bdf0a5b88acdc430000000000001976a914510052b5a1ab59a18ccaee53ab53477c6750f36188acc49c5921000000001976a914c1120654de9e85005befb76b39e90fb7231e107888ac00000000",
										"parents": {
											"8aedd0ff472c267d48258b15ab080427f772eb626bc2b09aab4212c3a9c07eb7": {
												"txid": "8aedd0ff472c267d48258b15ab080427f772eb626bc2b09aab4212c3a9c07eb7",
												"rawTx": "0200000001a89bcb7a89f4a487f75f53f5bfb712a9ee0aac1d694abb37f743221d2676c17c020000006b483045022100d37a63d0dda1f8e56b490421a9a558d37a6a9d8a6e8bc2a03bcd3bb2b38378ed02203bc9631e98b28a732fe83f173cf1acd53c1ccbf259d85abf663da413fb22413c4121039d755ce0ad729a36537dee465ddda45a754de215e9abd9fe5cb643996cc1b999ffffffff03359a0000000000001976a91430d1dcce4d59a26bf7bf97917807a3d4958409fd88acda430000000000001976a914510052b5a1ab59a18ccaee53ab53477c6750f36188ac737b5a21000000001976a9145335c337ef6091936de03e0e6ac1656ba52f980188ac00000000",
												"parents": {
													"7cc176261d2243f737bb4a691dac0aeea912b7bff5535ff787a4f4897acb9ba8": {
														"txid": "7cc176261d2243f737bb4a691dac0aeea912b7bff5535ff787a4f4897acb9ba8",
														"rawTx": "0200000001b09f38a6ec54d35193e029216a7bf3b10655938d96d57d4bef2fb4381ad4743a020000006b4830450221009d7762e9c5ff0a2896fa6bb42ebe3206559dcf135772341fa1a6e804134a178902201850f6518b11bbe559ea3fa445463eba287656f5bb0f4b147cd2288e432a5c5841210267f64e9a15ce83147477c35cf452242268210cbba8e06f9463618d8a4a65cd15ffffffff03295d0000000000001976a914983e253dd446c9e730d96c8266286d4ec89a428788ac51440000000000001976a914510052b5a1ab59a18ccaee53ab53477c6750f36188ac1c5a5b21000000001976a91450fdf7710fe198475b225e2c4e251c6094486fdc88ac00000000",
														"parents": {
															"3a74d41a38b42fef4b7dd5968d935506b1f37b6a2129e09351d354eca6389fb0": {
																"txid": "3a74d41a38b42fef4b7dd5968d935506b1f37b6a2129e09351d354eca6389fb0",
																"rawTx": "020000000172176e9eeef021f6b7b7bd8589536f58ebbffba740c4fec398f369090448c076020000006a47304402200f7967b57b8ce6f7de040eff8f62cb3590478a4dc11b86bfb8d444f6669f26d002207430b8140720fdb7a3b002ff22fd67a1b43cc1e814625a6b68900c55634d58034121035e8b97536ee92dfa17f3a66316929edf665c214ca7197daf350848e7dea5ccecffffffff036b5d0000000000001976a914a0c2a620ebf2fcdee0a01b23624f3901db33272988ac81440000000000001976a914510052b5a1ab59a18ccaee53ab53477c6750f36188ac30fc5b21000000001976a9141701e4ea323e0a1dfc519818c059341a338cf5fb88ac00000000",
																"proof": {
																	"index": 2,
																	"txOrId": "3a74d41a38b42fef4b7dd5968d935506b1f37b6a2129e09351d354eca6389fb0",
																	"target": "00000020d334108eb95ddefc0ea5ffbfc4ae7792cf5ed54bac9f80608d26d79c00000000f5b42d19624ac642ba93d0443c8296c742d1f0dd509878c1b1c9f71d1b4c9b102ac868616aa3001d04557ccd",
																	"nodes": [
																		"4c05bd4c079a2269f14a4347e959abaccb37697f70cbb08b8426e6674e09cd24",
																		"374c06c4ee471a2687498bd09bf42322aea3ca1e653cd23810baa1609b0ce25e",
																		"f4e18eb36ecde0719e1c8a2dc803768af250d76d08f4ab1a9fd2c08d905b6af3"
																	],
																	"targetType": "header"
																}
															}
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}`,
			hexString: "0101e10100000001f49f4b06f4f3244323fd11e7931838308780eafca389cd32b8ff614056088cfb010000006a4730440220470ec034c9f5a41fa5ebb752c1d7bfad5af7659861c52aae87768a6289bf110602207d584a686235800e9624b9ceeb9704b927c005b32310810987ec01652196ab7741210305d46481dd94e548669d30689e3b57d0a497e7265786308e3c6809dd8cee5dadffffffff02a00f0000000000001976a9147274c98d89bddefa863157f5a0f4789bc85856ac88ac81790000000000001976a914b77edad7bf765b4f1c412c49d9e7e549db98d6c988ac0000000001e20100000001c85091ec57f85d5cbb33a0926ff1bce469336f1912aaf73cd3977ff019e692de000000006b483045022100f2204fd3d87cab883c9d8d38068526eb653632c226c658480f72c1991c47f7e702207d2a20e6c477fe066b2a5976f1869006f21e34abdfa3fdf969c188e4b340f8d2412103d46926f6022e11ae35377a0277dc30bf0ed89282751301d0bd7720b590f9a1dbffffffff02a00f0000000000001976a91495cb3f890282d0aef458b9ca7d4a8f1b69c186b988ac92890000000000001976a9141c4f1e75d42057361e5d9443115c1938508f6e6388ac0000000001c00100000001f5668131b454c6d1960abc0cbf1be7fa938b0159560aa8cf9b9ce0def11898cd000000006b483045022100db3438332eec734c2393af37dfbd1c6ee1d00a5758c03a898a9cc3d3716f0798022077d1bdca0408651ab704feac5b9f1360d57db4819139d0518faf0eb4e48d1922412103ab3a2cf940e5f0aa0aa2bdd81c7ccc254de9d00dd677cc30e7486530ed9be092ffffffff01a3990000000000001976a914689547124e697984194a62f4c70506e7240962e688ac0000000001fd04010200000001b77ec0a9c31242ab9ab0c26b62eb72f7270408ab158b25487d262c47ffd0ed8a020000006b483045022100c473129b95c26dc5f43a42516f750efa8f0fa3173de102fa3d782d4605740c9e0220029da8e1f7651f10302a9bd492c401fc84f88c6444d264b1ce45ec42eae86b574121032097ea81a1d7211b1c6e25a6cc10723a716c63bbbda6f9fe74095a3ed6398a27ffffffff03399a0000000000001976a914e77f11b17677510e4e21f8e0b298119f3bdf0a5b88acdc430000000000001976a914510052b5a1ab59a18ccaee53ab53477c6750f36188acc49c5921000000001976a914c1120654de9e85005befb76b39e90fb7231e107888ac0000000001fd04010200000001a89bcb7a89f4a487f75f53f5bfb712a9ee0aac1d694abb37f743221d2676c17c020000006b483045022100d37a63d0dda1f8e56b490421a9a558d37a6a9d8a6e8bc2a03bcd3bb2b38378ed02203bc9631e98b28a732fe83f173cf1acd53c1ccbf259d85abf663da413fb22413c4121039d755ce0ad729a36537dee465ddda45a754de215e9abd9fe5cb643996cc1b999ffffffff03359a0000000000001976a91430d1dcce4d59a26bf7bf97917807a3d4958409fd88acda430000000000001976a914510052b5a1ab59a18ccaee53ab53477c6750f36188ac737b5a21000000001976a9145335c337ef6091936de03e0e6ac1656ba52f980188ac0000000001fd04010200000001b09f38a6ec54d35193e029216a7bf3b10655938d96d57d4bef2fb4381ad4743a020000006b4830450221009d7762e9c5ff0a2896fa6bb42ebe3206559dcf135772341fa1a6e804134a178902201850f6518b11bbe559ea3fa445463eba287656f5bb0f4b147cd2288e432a5c5841210267f64e9a15ce83147477c35cf452242268210cbba8e06f9463618d8a4a65cd15ffffffff03295d0000000000001976a914983e253dd446c9e730d96c8266286d4ec89a428788ac51440000000000001976a914510052b5a1ab59a18ccaee53ab53477c6750f36188ac1c5a5b21000000001976a91450fdf7710fe198475b225e2c4e251c6094486fdc88ac0000000001fd0301020000000172176e9eeef021f6b7b7bd8589536f58ebbffba740c4fec398f369090448c076020000006a47304402200f7967b57b8ce6f7de040eff8f62cb3590478a4dc11b86bfb8d444f6669f26d002207430b8140720fdb7a3b002ff22fd67a1b43cc1e814625a6b68900c55634d58034121035e8b97536ee92dfa17f3a66316929edf665c214ca7197daf350848e7dea5ccecffffffff036b5d0000000000001976a914a0c2a620ebf2fcdee0a01b23624f3901db33272988ac81440000000000001976a914510052b5a1ab59a18ccaee53ab53477c6750f36188ac30fc5b21000000001976a9141701e4ea323e0a1dfc519818c059341a338cf5fb88ac0000000002d60202b09f38a6ec54d35193e029216a7bf3b10655938d96d57d4bef2fb4381ad4743acd7c55041d00a36a6168c82a109b4c1b1df7c9b1c1789850ddf0d142c796823c44d093ba42c64a62192db4f5000000009cd7268d60809fac4bd55ecf9277aec4bfffa50efcde5db98e1034d320000000030024cd094e67e626848bb0cb707f6937cbacab59e947434af169229a074cbd054c005ee20c9b60a1ba1038d23c651ecaa3ae2223f49bd08b4987261a47eec4064c3700f36a5b908dc0d29f1aabf4086dd750f28a7603c82d8a1c9e71e0cd6eb38ee1f4",
		},
		"with mapi responses": {
			jsonString: `{
				"rawTx": "0100000001f49f4b06f4f3244323fd11e7931838308780eafca389cd32b8ff614056088cfb010000006a4730440220470ec034c9f5a41fa5ebb752c1d7bfad5af7659861c52aae87768a6289bf110602207d584a686235800e9624b9ceeb9704b927c005b32310810987ec01652196ab7741210305d46481dd94e548669d30689e3b57d0a497e7265786308e3c6809dd8cee5dadffffffff02a00f0000000000001976a9147274c98d89bddefa863157f5a0f4789bc85856ac88ac81790000000000001976a914b77edad7bf765b4f1c412c49d9e7e549db98d6c988ac00000000",
				"mapiResponses": [{
					"callbackPayload": "{\"flags\":2,\"index\":1,\"txOrId\":\"8f4d96ae3cc7b7e7e13615d1ed9ea6bd6aea6c1bdeeb5aff51351b82562046a1\",\"target\":{\"hash\":\"000000000000bd24a0766c1bfc01a66fe623994b1b99fdb1472e5c0d5106574d\",\"confirmations\":1,\"height\":1452203,\"version\":536870912,\"versionHex\":\"20000000\",\"merkleroot\":\"d153734159acad9ee3a77a50d4afa6366e39324f6728a1b6f58007891309a371\",\"num_tx\":3,\"time\":1633101675,\"mediantime\":1633100792,\"nonce\":2490264034,\"bits\":\"1b576eea\",\"difficulty\":749.5431539054099,\"chainwork\":\"0000000000000000000000000000000000000000000000f617cc7149d0f09eb7\",\"previousblockhash\":\"00000000001c6dd44e911cf312b693b1113b2e03239a4b02dbe592fa7fd3727d\"},\"nodes\":[\"8055b2e2cd33fa69e44aebf5b44af59dc9fb57e5803d8bb7da3eee8ed71aaa64\",\"6cae019ee7daf29c778d6e11b69d4922b0ab31eff6cc9ee2515f592cda7cc296\"]}",
					"apiVersion": "1.3.0",
					"timestamp": "2021-10-01T15:21:22.7409219Z",
					"minerId": "030d1fe5c1b560efe196ba40540ce9017c20daa9504c4c4cec6184fc702d9f274e",
					"blockHash": "000000000000bd24a0766c1bfc01a66fe623994b1b99fdb1472e5c0d5106574d",
					"blockHeight": 1452203,
					"callbackTxId": "8f4d96ae3cc7b7e7e13615d1ed9ea6bd6aea6c1bdeeb5aff51351b82562046a1",
					"callbackReason": "merkleProof"
				}],
				"parents": {
					"fb8c08564061ffb832cd89a3fcea808730381893e711fd234324f3f4064b9ff4": {
						"rawTx": "0100000001c85091ec57f85d5cbb33a0926ff1bce469336f1912aaf73cd3977ff019e692de000000006b483045022100f2204fd3d87cab883c9d8d38068526eb653632c226c658480f72c1991c47f7e702207d2a20e6c477fe066b2a5976f1869006f21e34abdfa3fdf969c188e4b340f8d2412103d46926f6022e11ae35377a0277dc30bf0ed89282751301d0bd7720b590f9a1dbffffffff02a00f0000000000001976a91495cb3f890282d0aef458b9ca7d4a8f1b69c186b988ac92890000000000001976a9141c4f1e75d42057361e5d9443115c1938508f6e6388ac00000000",
						"parents": {
							"de92e619f07f97d33cf7aa12196f3369e4bcf16f92a033bb5c5df857ec9150c8": {
								"rawTx": "0100000001f5668131b454c6d1960abc0cbf1be7fa938b0159560aa8cf9b9ce0def11898cd000000006b483045022100db3438332eec734c2393af37dfbd1c6ee1d00a5758c03a898a9cc3d3716f0798022077d1bdca0408651ab704feac5b9f1360d57db4819139d0518faf0eb4e48d1922412103ab3a2cf940e5f0aa0aa2bdd81c7ccc254de9d00dd677cc30e7486530ed9be092ffffffff01a3990000000000001976a914689547124e697984194a62f4c70506e7240962e688ac00000000",
								"proof": {
									"index": 2,
									"txOrId": "de92e619f07f97d33cf7aa12196f3369e4bcf16f92a033bb5c5df857ec9150c8",
									"target": "00000020d334108eb95ddefc0ea5ffbfc4ae7792cf5ed54bac9f80608d26d79c00000000f5b42d19624ac642ba93d0443c8296c742d1f0dd509878c1b1c9f71d1b4c9b102ac868616aa3001d04557ccd",
									"nodes": [
										"4c05bd4c079a2269f14a4347e959abaccb37697f70cbb08b8426e6674e09cd24",
										"374c06c4ee471a2687498bd09bf42322aea3ca1e653cd23810baa1609b0ce25e",
										"f4e18eb36ecde0719e1c8a2dc803768af250d76d08f4ab1a9fd2c08d905b6af3"
									],
									"targetType": "header"
								}
							}
						}
					}
				}
			}`,
			hexString: "0101e10100000001f49f4b06f4f3244323fd11e7931838308780eafca389cd32b8ff614056088cfb010000006a4730440220470ec034c9f5a41fa5ebb752c1d7bfad5af7659861c52aae87768a6289bf110602207d584a686235800e9624b9ceeb9704b927c005b32310810987ec01652196ab7741210305d46481dd94e548669d30689e3b57d0a497e7265786308e3c6809dd8cee5dadffffffff02a00f0000000000001976a9147274c98d89bddefa863157f5a0f4789bc85856ac88ac81790000000000001976a914b77edad7bf765b4f1c412c49d9e7e549db98d6c988ac0000000003fdb7047b2263616c6c6261636b5061796c6f6164223a227b5c22666c6167735c223a322c5c22696e6465785c223a312c5c2274784f7249645c223a5c22386634643936616533636337623765376531333631356431656439656136626436616561366331626465656235616666353133353162383235363230343661315c222c5c227461726765745c223a7b5c22686173685c223a5c22303030303030303030303030626432346130373636633162666330316136366665363233393934623162393966646231343732653563306435313036353734645c222c5c22636f6e6669726d6174696f6e735c223a312c5c226865696768745c223a313435323230332c5c2276657273696f6e5c223a3533363837303931322c5c2276657273696f6e4865785c223a5c2232303030303030305c222c5c226d65726b6c65726f6f745c223a5c22643135333733343135396163616439656533613737613530643461666136333636653339333234663637323861316236663538303037383931333039613337315c222c5c226e756d5f74785c223a332c5c2274696d655c223a313633333130313637352c5c226d656469616e74696d655c223a313633333130303739322c5c226e6f6e63655c223a323439303236343033342c5c22626974735c223a5c2231623537366565615c222c5c22646966666963756c74795c223a3734392e353433313533393035343039392c5c22636861696e776f726b5c223a5c22303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030306636313763633731343964306630396562375c222c5c2270726576696f7573626c6f636b686173685c223a5c22303030303030303030303163366464343465393131636633313262363933623131313362326530333233396134623032646265353932666137666433373237645c227d2c5c226e6f6465735c223a5b5c22383035356232653263643333666136396534346165626635623434616635396463396662353765353830336438626237646133656565386564373161616136345c222c5c22366361653031396565376461663239633737386436653131623639643439323262306162333165666636636339656532353135663539326364613763633239365c225d7d222c2261706956657273696f6e223a22312e332e30222c2274696d657374616d70223a22323032312d31302d30315431353a32313a32322e373430393231395a222c226d696e65724964223a22303330643166653563316235363065666531393662613430353430636539303137633230646161393530346334633463656336313834666337303264396632373465222c22626c6f636b48617368223a2230303030303030303030303062643234613037363663316266633031613636666536323339393462316239396664623134373265356330643531303635373464222c22626c6f636b486569676874223a313435323230332c2263616c6c6261636b54784964223a2238663464393661653363633762376537653133363135643165643965613662643661656136633162646565623561666635313335316238323536323034366131222c2263616c6c6261636b526561736f6e223a226d65726b6c6550726f6f66227d01e20100000001c85091ec57f85d5cbb33a0926ff1bce469336f1912aaf73cd3977ff019e692de000000006b483045022100f2204fd3d87cab883c9d8d38068526eb653632c226c658480f72c1991c47f7e702207d2a20e6c477fe066b2a5976f1869006f21e34abdfa3fdf969c188e4b340f8d2412103d46926f6022e11ae35377a0277dc30bf0ed89282751301d0bd7720b590f9a1dbffffffff02a00f0000000000001976a91495cb3f890282d0aef458b9ca7d4a8f1b69c186b988ac92890000000000001976a9141c4f1e75d42057361e5d9443115c1938508f6e6388ac0000000001c00100000001f5668131b454c6d1960abc0cbf1be7fa938b0159560aa8cf9b9ce0def11898cd000000006b483045022100db3438332eec734c2393af37dfbd1c6ee1d00a5758c03a898a9cc3d3716f0798022077d1bdca0408651ab704feac5b9f1360d57db4819139d0518faf0eb4e48d1922412103ab3a2cf940e5f0aa0aa2bdd81c7ccc254de9d00dd677cc30e7486530ed9be092ffffffff01a3990000000000001976a914689547124e697984194a62f4c70506e7240962e688ac0000000002d60202c85091ec57f85d5cbb33a0926ff1bce469336f1912aaf73cd3977ff019e692decd7c55041d00a36a6168c82a109b4c1b1df7c9b1c1789850ddf0d142c796823c44d093ba42c64a62192db4f5000000009cd7268d60809fac4bd55ecf9277aec4bfffa50efcde5db98e1034d320000000030024cd094e67e626848bb0cb707f6937cbacab59e947434af169229a074cbd054c005ee20c9b60a1ba1038d23c651ecaa3ae2223f49bd08b4987261a47eec4064c3700f36a5b908dc0d29f1aabf4086dd750f28a7603c82d8a1c9e71e0cd6eb38ee1f4",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			j := []byte(test.jsonString)
			var e Envelope
			err := json.Unmarshal(j, &e)
			if err != nil {
				assert.Error(t, err, "Couldn't decode jsonString")
			}

			b, err := hex.DecodeString(test.hexString)
			if err != nil {
				assert.Error(t, err, "Couldn't decode hexString")
			}

			efromB, err := NewEnvelopeFromBytes(b)
			if err != nil {
				assert.Error(t, err, "Couldn't create envelope from bytes")
			}

			bFromE, err := e.Bytes()
			if err != nil {
				assert.Error(t, err, "Couldn't convert envelope to bytes")
			}

			fmt.Printf("%v bytes: \n\n%+v\n\n", name, hex.EncodeToString(*bFromE))
			fmt.Printf("e: \n\n%+v\n\n", e)
			fmt.Printf("efromB: \n\n%+v\n\n", efromB)

			assert.Equal(t, b, *bFromE)
			assert.NoError(t, err)
		})
	}
}
