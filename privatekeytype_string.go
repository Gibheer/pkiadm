// Code generated by "stringer -type PrivateKeyType"; DO NOT EDIT

package pkiadm

import "fmt"

const _PrivateKeyType_name = "rsaecdsaed25519"

var _PrivateKeyType_index = [...]uint8{0, 3, 8, 15}

func (i PrivateKeyType) String() string {
	if i >= PrivateKeyType(len(_PrivateKeyType_index)-1) {
		return fmt.Sprintf("PrivateKeyType(%d)", i)
	}
	return _PrivateKeyType_name[_PrivateKeyType_index[i]:_PrivateKeyType_index[i+1]]
}

func StringToPrivateKeyType(t string) (PrivateKeyType, error) {
	switch t {
	case "rsa":
		return PKTRSA, nil
	case "ecdsa":
		return PKTECDSA, nil
	case "ed25519":
		return PKTED25519, nil
	default:
		return PKTUnknown, fmt.Errorf("unknown private key type")
	}
}
