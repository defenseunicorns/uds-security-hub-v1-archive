package scan

type trivyScannable interface {
	TrivyCommand() []string
}

type ArtifactNameOverride interface {
	ArtifactNameOverride() string
}

type remoteScannable struct {
	ImageRef string
}

func (r *remoteScannable) TrivyCommand() []string {
	return []string{"image", "--image-src=remote", r.ImageRef}
}

type cyclonedxSBOMScannable struct {
	ArtifactName string
	SBOMFile     string
}

func (c cyclonedxSBOMScannable) ArtifactNameOverride() string {
	return c.ArtifactName
}

func (c cyclonedxSBOMScannable) TrivyCommand() []string {
	return []string{"sbom", c.SBOMFile}
}

type rootfsScannable struct {
	ArtifactName string
	RootFSDir    string
}

func (r rootfsScannable) TrivyCommand() []string {
	return []string{"rootfs", r.RootFSDir}
}

func (r rootfsScannable) ArtifactNameOverride() string {
	return r.ArtifactName
}
