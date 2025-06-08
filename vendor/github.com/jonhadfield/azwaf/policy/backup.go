package policy

import (
        "context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jonhadfield/azwaf/config"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/Azure/azure-storage-blob-go/azblob"

	"github.com/jonhadfield/azwaf/session"
	"github.com/sirupsen/logrus"
        terminal "golang.org/x/term"
)

const (
       blockBlobUploadBlockSize = 4 * 1024 * 1024
       blockBlobParallelism     = 16
       defaultTerminalWidth     = 80
)

// BackupPoliciesInput are the arguments provided to the BackupPolicies function.
type BackupPoliciesInput struct {
	BaseCLIInput
	Path                     string
	RIDs                     []string
	StorageAccountResourceID string
	ContainerURL             string
	FailFast                 bool
}

func (in *BackupPoliciesInput) Validate() error {
	if in.SubscriptionID == "" && len(in.RIDs) == 0 {
		return fmt.Errorf("%s - subscription-id required if resource ids not specified",
			GetFunctionName())
	}

	if err := validateSubscriptionID(in.SubscriptionID); err != nil {
		return err
	}

	return nil
}

// BackupPolicies retrieves policies within a subscription and writes them, with meta-data, to individual json files
func BackupPolicies(in *BackupPoliciesInput) error {
	funcName := GetFunctionName()

	if err := in.Validate(); err != nil {
		return err
	}

	s := session.New()

	// fail if only one of the storage account destination required parameters been defined
	if (in.StorageAccountResourceID != "" && in.ContainerURL == "") || (in.StorageAccountResourceID == "" && in.ContainerURL != "") {
		return fmt.Errorf("%s - both storage account resource id and container url are required for backups to Azure Storage",
			funcName)
	}

	// fail if neither path nor storage account details are provided
	if in.StorageAccountResourceID == "" && in.Path == "" {
		return fmt.Errorf(
			"%s - either path or storage account details are required",
			funcName)
	}

	if len(in.RIDs) == 0 && in.SubscriptionID == "" {
		return fmt.Errorf(
			"%s - either subscription id or resource ids are required",
			funcName)
	}

	o, err := GetWrappedPoliciesFromRawIDs(s, GetWrappedPoliciesInput{
		SubscriptionID:    in.SubscriptionID,
		AppVersion:        in.AppVersion,
		FilterResourceIDs: in.RIDs,
		Config:            in.ConfigPath,
	})
	if err != nil {
		return err
	}

	logrus.Debugf("%s | retrieved %d policies", funcName, len(o.Policies))

	var containerURL azblob.ContainerURL

	if in.StorageAccountResourceID != "" {
		sari := config.ParseResourceID(in.StorageAccountResourceID)
		var storageAccountsClient *armstorage.AccountsClient
		storageAccountsClient, err = armstorage.NewAccountsClient(sari.SubscriptionID, s.ClientCredential, nil)
		if err != nil {
			return fmt.Errorf("failed to create storage account client - %s", err.Error())
		}

		ctx := context.Background()

		var sac armstorage.AccountsClientListKeysResponse

		sac, oerr := storageAccountsClient.ListKeys(ctx, sari.ResourceGroup, sari.Name, nil)
		if oerr != nil {
			return fmt.Errorf("failed to list keys for storage account %s - %s", sari.Name, oerr.Error())
		}

		b := sac.Keys[0]

		credential, oerr := azblob.NewSharedKeyCredential(sari.Name, *b.Value)
		if oerr != nil {
			return fmt.Errorf("invalid credentials with error: %s", oerr.Error())
		}

		p := azblob.NewPipeline(credential, azblob.PipelineOptions{})

		var cu *url.URL

		cu, oerr = url.Parse(in.ContainerURL)
		if oerr != nil {
			return oerr
		}

		containerURL = azblob.NewContainerURL(*cu, p)
	}

	return backupPolicies(o.Policies, &containerURL, in.FailFast, in.Quiet, in.Path)
}

// BackupPolicy takes a WrappedPolicy as input and creates a json file that can later be restored
func BackupPolicy(p *WrappedPolicy, containerURL *azblob.ContainerURL, failFast, quiet bool, path string) (err error) {
	funcName := GetFunctionName()
	now := time.Now().UTC()
	dateString := now.UTC().Format("20060102150405")
	p.Date = now

	var cwd string

	if !quiet {
		var oerr error

		cwd, oerr = os.Getwd()
		if oerr != nil {
			return oerr
		}

		msg := fmt.Sprintf("backing up Policy: %s", p.Name)
		statusOutput := PadToWidth(msg, " ", 0, true)
		fd := int(os.Stdout.Fd())

		width, _, terr := terminal.GetSize(fd)
		if terr != nil {
			return fmt.Errorf(terr.Error(), funcName)
		}

		if len(statusOutput) == width {
			fmt.Printf(statusOutput[0:width-3] + "   \r")
		} else {
			fmt.Print(statusOutput)
		}
	}

	pj, oerr := json.MarshalIndent(p, "", "    ")
	if oerr != nil {
		if failFast {
			return oerr
		}

		logrus.Error(err)
	}

	fName := fmt.Sprintf("%s+%s+%s+%s.json", p.SubscriptionID, p.ResourceGroup, p.Name, dateString)

	// write to storage account
	if containerURL != nil && containerURL.String() != "" {
		ctx := context.Background()

		blobURL := containerURL.NewBlockBlobURL(fName)

		if !quiet {
			logrus.Infof("uploading file with blob name: %s\n", fName)
		}

               _, oerr = azblob.UploadBufferToBlockBlob(ctx, pj, blobURL, azblob.UploadToBlockBlobOptions{
                       BlockSize:   blockBlobUploadBlockSize,
                       Parallelism: blockBlobParallelism,
               })
		if oerr != nil {
			return oerr
		}
	}

	if path != "" {
		err = writeBackupToFile(pj, cwd, fName, quiet, path)
		if err != nil {
			return fmt.Errorf(err.Error(), funcName)
		}
	}

	return
}

func writeBackupToFile(pj []byte, cwd, fName string, quiet bool, path string) (err error) {
	funcName := GetFunctionName()

	fp := filepath.Join(path, fName)
	// #nosec
	f, err := os.Create(fp)
	if err != nil {
		return fmt.Errorf("%s - failed to create file: %s with error: %s", funcName, fp, err.Error())
	}

	_, err = f.Write(pj)
	if err != nil {
		_ = f.Close()

		return
	}

	_ = f.Close()

	if !quiet {
		op := filepath.Clean(fp)
		if strings.HasPrefix(op, cwd) {
			op, err = filepath.Rel(cwd, op)
			if err != nil {
				return fmt.Errorf("%s - %s", funcName, err.Error())
			}

			op = "./" + op
		}

		logrus.Infof("backup written to: %s", op)
	}

	return
}

// backupPolicies accepts a list of WrappedPolicys and calls BackupPolicy with each
func backupPolicies(policies []WrappedPolicy, containerURL *azblob.ContainerURL, failFast, quiet bool, path string) (err error) {
	for x := range policies {
		err = BackupPolicy(&policies[x], containerURL, failFast, quiet, path)

		if failFast {
			return
		}
	}

	return
}

func PadToWidth(input, char string, inputLengthOverride int, trimToWidth bool) string {
	lines := strings.Split(strings.TrimSuffix(input, "\n"), "\n")

       width, _, err := terminal.GetSize(int(os.Stdout.Fd()))
       if err != nil || width == -1 {
               width = defaultTerminalWidth
       }

	for i, line := range lines {
		length := len(line)
		if inputLengthOverride > 0 {
			length = inputLengthOverride
		}

		if length >= width {
			if trimToWidth {
				return line[:width]
			}

			return input
		}

		padding := width - length
		if inputLengthOverride != 0 {
			padding = width - inputLengthOverride
		}

		suffix := "\n"
		if i == len(lines)-1 {
			suffix = "\r"
		}

		lines[i] = fmt.Sprintf("%s%s%s", line, strings.Repeat(char, padding), suffix)
	}

	return strings.Join(lines, "")
}
