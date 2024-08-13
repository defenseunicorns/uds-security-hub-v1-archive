package scan

type imageRef interface {
	TrivyCommand() []string
}

type ArtifactNameOverride interface {
	ArtifactNameOverride() string
}

type remoteImageRef struct {
	ImageRef string
}

func (r *remoteImageRef) TrivyCommand() []string {
	return []string{"image", "--image-src=remote", r.ImageRef}
}

type cyclonedxSBOMRef struct {
	ArtifactName string
	SBOMFile     string
}

func (c cyclonedxSBOMRef) ArtifactNameOverride() string {
	return c.ArtifactName
}

func (c cyclonedxSBOMRef) TrivyCommand() []string {
	return []string{"sbom", c.SBOMFile}
}

type rootfsRef struct {
	ArtifactName string
	RootFSDir    string
}

func (r rootfsRef) TrivyCommand() []string {
	return []string{"rootfs", r.RootFSDir}
}

func (r rootfsRef) ArtifactNameOverride() string {
	return r.ArtifactName
}
