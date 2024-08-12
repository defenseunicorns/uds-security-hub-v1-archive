package scan

type imageRef interface {
	TrivyCommand() []string
}

type remoteImageRef struct {
	ImageRef string
}

func (r *remoteImageRef) TrivyCommand() []string {
	return []string{"image", "--image-src=remote", r.ImageRef}
}

type cyclonedxSbomRef struct {
	ArtifactName string
	SBOMFile     string
}

func (s *cyclonedxSbomRef) TrivyCommand() []string {
	return []string{"sbom", s.SBOMFile}
}

type rootfsRef struct {
	ArtifactName string
	RootFSDir    string
}

func (r rootfsRef) TrivyCommand() []string {
	return []string{"rootfs", r.RootFSDir}
}
