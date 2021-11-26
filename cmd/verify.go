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
	"fmt"
	"io/ioutil"
	"os"

	"github.com/Joh4nnesHartl/gosig/key"
	"github.com/Joh4nnesHartl/gosig/signature"
	"github.com/spf13/cobra"
)

// verifyCmd represents the verify command
var verifyCmd = &cobra.Command{
	Use:  "verify",
	Long: "verify verifies if the <data-signature> over <data> with the corresponding <public-key> is valid.",
	Args: cobra.ExactArgs(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		_, err := os.Stat(args[0])
		if err != nil {
			return fmt.Errorf("data file %s doesnt exist", args[0])
		}

		_, err = os.Stat(args[1])
		if err != nil {
			return fmt.Errorf("signature %s doesnt exist", args[1])
		}

		_, err = os.Stat(args[2])
		if err != nil {
			return fmt.Errorf("public key %s doesnt exist", args[2])
		}

		data, err := ioutil.ReadFile(args[0])
		if err != nil {
			return err
		}

		signatureRAW, err := ioutil.ReadFile(args[1])
		if err != nil {
			return err
		}

		publicKeyPEM, err := ioutil.ReadFile(args[2])
		if err != nil {
			return err
		}

		sig, err := signature.ParseSignature(string(signatureRAW))
		if err != nil {
			return err
		}

		publicKey, err := key.ParsePublicKey(publicKeyPEM)
		if err != nil {
			return err
		}

		if ok := signature.VerifySignature(data, sig, publicKey); ok {
			fmt.Print("Valid Signature! :)")
		} else {
			fmt.Print("Invalid Signature! :(")
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(verifyCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// verifyCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// verifyCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
