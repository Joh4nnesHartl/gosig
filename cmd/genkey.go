/*
Copyright © 2021 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/Joh4nnesHartl/gosig/key"
	"github.com/spf13/cobra"
)

// genkeyCmd represents the genkey command
var genkeyCmd = &cobra.Command{
	Use:  "genkey",
	Long: `genkey generates a public & private key pair in the current directory <key-name> & <key-name>.pub`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		privName := args[0]
		pubName := privName + ".pub"

		publicKey, privateKey, err := key.GenerateKeyPair()
		if err != nil {
			return err
		}

		if _, err := os.Stat(pubName); errors.Is(err, os.ErrNotExist) {
			publicKeyPEM, err := key.SerializePublicKey(publicKey)
			if err != nil {
				return err
			}

			ioutil.WriteFile(pubName, publicKeyPEM, 0644)
		} else {
			return fmt.Errorf("error: public key %s already exists", pubName)
		}

		if _, err := os.Stat(privName); errors.Is(err, os.ErrNotExist) {
			privateKeyPEM, err := key.SerializePrivateKey(privateKey)
			if err != nil {
				return err
			}

			ioutil.WriteFile(privName, privateKeyPEM, 0644)
		} else {
			return fmt.Errorf("error: private key %s already exists", privName)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(genkeyCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// genkeyCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// genkeyCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
