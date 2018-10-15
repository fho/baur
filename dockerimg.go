package baur

import (
	"fmt"

	"github.com/pkg/errors"

	"github.com/simplesurance/baur/digest"
)

// RemoteDockerImg represents a docker image in a docker repository
type RemoteDockerImg struct {
	repository string
	digest     string
	path       string
}

// NewRemoteDockerImg creates a RemoteDockerImg
func NewRemoteDockerImg(repository, digest string) *RemoteDockerImg {
	return &RemoteDockerImg{
		digest:     digest,
		repository: repository,
		path:       fmt.Sprintf("%s@%s", repository, digest),
	}
}

// Digest returns the image digest
func (r *RemoteDockerImg) Digest() (digest.Digest, error) {
	d, err := digest.FromString(r.digest)
	if err != nil {
		return digest.Digest{}, errors.Wrap(err, "parsing digest failed")
	}

	return *d, nil
}

// URL returns it's URL
func (r *RemoteDockerImg) URL() string {
	return fmt.Sprintf("docker://%s", r.path)
}

// String returns a string representation
func (r *RemoteDockerImg) String() string {
	return r.URL()
}
