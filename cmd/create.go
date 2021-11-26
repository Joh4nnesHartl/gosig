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

// createCmd represents the create command
var createCmd = &cobra.Command{
	Use:  "create",
	Long: `makes a signature over <data> with the <private-key>: the signature is saved as <data>.sig`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		_, err := os.Stat(args[0])
		if err != nil {
			return fmt.Errorf("file %s doesnt exist", args[0])
		}

		_, err = os.Stat(args[1])
		if err != nil {
			return fmt.Errorf("private key %s doesnt exist", args[1])
		}

		data, err := ioutil.ReadFile(args[0])
		if err != nil {
			return err
		}

		privPEM, err := ioutil.ReadFile(args[1])
		if err != nil {
			return err
		}

		privKey, err := key.ParsePrivatKey(privPEM)
		if err != nil {
			return err
		}

		signature, err := signature.CreateSignature(data, privKey)
		if err != nil {
			return err
		}

		err = ioutil.WriteFile(args[0]+".sig", []byte(signature.Serialize()), 0644)
		if err != nil {
			return err
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(createCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// createCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// createCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
