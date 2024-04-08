package workspaces

import (
	iacTypes "github.com/aquasecurity/trivy-policies/pkg/types"
)

type WorkSpaces struct {
	WorkSpaces []WorkSpace
}

type WorkSpace struct {
	Metadata   iacTypes.Metadata
	RootVolume Volume
	UserVolume Volume
}

type Volume struct {
	Metadata   iacTypes.Metadata
	Encryption Encryption
}

type Encryption struct {
	Metadata iacTypes.Metadata
	Enabled  iacTypes.BoolValue
}
