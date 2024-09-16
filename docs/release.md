# Release Instructions

Please follow these steps to perform a release:

1. **Verify and Create a Signed Git Tag Based on the Milestone**

   First, kindly ensure your GPG/SSH keys are valid and properly configured for signing tags in GitHub. Determine the version number based on the milestone and verify it. Then, please execute the following command to create a signed Git tag:

   ```bash
   git tag --sign v0.1.0 -m "v0.1.0"
   ```

2. **Verify Automated Workflows**

   Please ensure that the following automated workflows execute successfully:
   - Go Releaser generation (`slsa.yaml`)
   - Docker image creation (`apko.yaml`)

3. **Check GitHub Release Draft**

   Kindly verify that the GitHub release is created as a draft. Once all checks are complete and everything is fine, please mark it as non-draft.

4. **Update Workflow with Latest Container Image**

   Please update the workflow at [s3-prod.yaml](https://github.com/defenseunicorns/uds-security-hub-scanning/actions/workflows/s3-prod.yaml) with the latest container image. Ensure the image tag is correct and up-to-date.

5. **Run the Workflow and Save SQLite DB**

   Please execute the workflow and save the SQLite database as an artifact. This process takes about 35 minutes.

6. **Validate Database Results**

   Kindly download the SQLite database and ensure that the results are successful in the `reports` table.

---

- **Security:**
  - Please ensure all Git tags are signed to verify authenticity.
