/*
 * MinIO Cloud Storage, (C) 2016, 2017 MinIO, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cmd

import (
	"testing"
)

func testAuthenticate(authType string, t *testing.T) {
	/*
		obj, fsDir, err := prepareFS()
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(fsDir)
		if err = newTestConfig(globalMinioDefaultRegion, obj); err != nil {
			t.Fatal(err)
		}

		cred, err := auth.GetNewCredentials()
		if err != nil {
			t.Fatalf("Error getting new credentials: %s", err)
		}

		globalActiveCred = cred

		// Define test cases.
		testCases := []struct {
			accessKey   string
			secretKey   string
			expectedErr error
		}{
			// Access key (less than 3 chrs) too small.
			{"u1", cred.SecretKey, auth.ErrInvalidAccessKeyLength},
			// Secret key (less than 8 chrs) too small.
			{cred.AccessKey, "pass", auth.ErrInvalidSecretKeyLength},
			// Authentication error.
			{"myuser", "mypassword", errInvalidAccessKeyID},
			// Authentication error.
			{cred.AccessKey, "mypassword", errAuthentication},
			// Success.
			{cred.AccessKey, cred.SecretKey, nil},
		}

		// Run tests.
		for _, testCase := range testCases {
			var err error
			if authType == "web" {
				_, err = authenticateWeb(testCase.accessKey, testCase.secretKey)
			} else if authType == "url" {
				_, err = authenticateURL(testCase.accessKey, testCase.secretKey)
			}

			if testCase.expectedErr != nil {
				if err == nil {
					t.Fatalf("%+v: expected: %s, got: <nil>", testCase, testCase.expectedErr)
				}
				if testCase.expectedErr.Error() != err.Error() {
					t.Fatalf("%+v: expected: %s, got: %s", testCase, testCase.expectedErr, err)
				}
			} else if err != nil {
				t.Fatalf("%+v: expected: <nil>, got: %s", testCase, err)
			}
		}
	*/
}

func TestAuthenticateWeb(t *testing.T) {
	testAuthenticate("web", t)
}

func TestAuthenticateURL(t *testing.T) {
	testAuthenticate("url", t)
}
