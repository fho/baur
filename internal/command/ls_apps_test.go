package command

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/simplesurance/baur/v3/internal/testutils/gittest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLsAppsJSON(t *testing.T) {
	initTest(t)

	repoDir := filepath.Join(testdataDir, "multitasks")
	err := os.Chdir(repoDir)
	require.NoError(t, err)

	gittest.CreateRepository(t, repoDir)

	lsAppsCmd := newLsAppsCmd()
	lsAppsCmd.format.Val = "json"
	stdoutBuf, _ := interceptCmdOutput(t)
	require.NoError(t, lsAppsCmd.Execute())

	var res []map[string]any
	require.NoError(t, json.Unmarshal(stdoutBuf.Bytes(), &res))
	assert.Len(t, res, 4)
	assert.Contains(t, res, map[string]any{
		"Name": "app3",
		"Path": "app3",
	})
}
