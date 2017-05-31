// Code generated by "stringer -type ResourceType"; DO NOT EDIT

package pkiadm

import "fmt"

func (i ResourceType) String() string {
	switch i {
	case RTPrivateKey:
		return "private"
	case RTPublicKey:
		return "public"
	case RTCSR:
		return "csr"
	case RTCertificate:
		return "cert"
	case RTSubject:
		return "subject"
	case RTSerial:
		return "serial"
	case RTLocation:
		return "location"
	case RTUnknown:
		return "unknown"
	default:
		return fmt.Sprintf("ResourceType(%d)", i)
	}
}

func StringToResourceType(in string) (ResourceType, error) {
	switch in {
	case "private":
		return RTPrivateKey, nil
	case "public":
		return RTPublicKey, nil
	case "csr":
		return RTCSR, nil
	case "cert":
		return RTCertificate, nil
	case "location":
		return RTLocation, nil
	case "subject":
		return RTSubject, nil
	case "serial":
		return RTSerial, nil
	default:
		return RTUnknown, fmt.Errorf("unknown resource type")
	}
}
