// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2020 Modio AB

//! A crate named caramel-client. The crate provides library API used to implement a Caramel Client in Rust.
//!
//! See [Caramel Client project](https://gitlab.com/ModioAB/caramel-client-rs) on GitLab for more information.

use caramel_client::CcError;
use std::os::unix::fs::PermissionsExt;

#[derive(Debug, std::cmp::PartialEq)]
pub enum FileModeComparison {
    MatchingPermissions,
    UserOrGroupPermissionsDiffers,
}

/// Verifies that a file has a certain permission mode
///
/// # Errors
/// * `Error` if file permission of 'others' doesn't matches target permission mode.
pub fn verify_file_permissions(
    filename: &std::path::Path,
    target_ugw_perm: u32,
) -> Result<(FileModeComparison, u32), CcError> {
    let meta = match std::fs::metadata(filename) {
        Ok(m) => m,
        Err(_) => return Err(CcError::PrivateKeyNotFound),
    };

    let perm = meta.permissions().mode();
    let file_ugw_perm = perm & 0o777;

    if (file_ugw_perm & 0o007) != (target_ugw_perm & 0o007) {
        Err(CcError::OtherUsersFilePermissionMismatch {
            filename: filename.display().to_string(),
            file_perm: file_ugw_perm,
            default_perm: target_ugw_perm,
            default_other_perm: target_ugw_perm & 0o7,
        })
    } else if file_ugw_perm == target_ugw_perm {
        Ok((FileModeComparison::MatchingPermissions, file_ugw_perm))
    } else {
        Ok((
            FileModeComparison::UserOrGroupPermissionsDiffers,
            file_ugw_perm,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::Path;
    extern crate testing_logger;

    use super::*;

    fn create_file_with_specific_permission(file_perm: u32, file_name: &str) -> std::path::PathBuf {
        let test_dir_name = format!("{}{}", "caramel_client_unit_tests_", whoami::username());
        let tmp_dir = std::env::temp_dir().join(test_dir_name);
        if !tmp_dir.exists() {
            std::fs::create_dir(&tmp_dir).ok();
        }
        let file_path = tmp_dir.join(file_name);
        OpenOptions::new()
            .write(true)
            .create(true)
            .mode(file_perm)
            .open(&file_path)
            .unwrap();

        file_path
    }

    #[test]
    fn test_verify_file_permissions_should_return_matching_permissions_when_file_permissions_matches(
    ) {
        let file_perm = 0o600;
        let file_path =
            create_file_with_specific_permission(file_perm, "file_600_expected_600.txt");
        let (result, _) = verify_file_permissions(&file_path, file_perm).unwrap();
        std::fs::remove_file(file_path).unwrap();

        assert_eq!(result, FileModeComparison::MatchingPermissions);
    }

    #[test]
    fn test_verify_file_permissions_should_return_user_or_group_permissions_differs_when_user_permission_differs(
    ) {
        let file_perm = 0o400;
        let expected_file_perm = 0o600;
        let file_path =
            create_file_with_specific_permission(file_perm, "file_400_expected_600.txt");
        let (result, _) = verify_file_permissions(&file_path, expected_file_perm).unwrap();
        std::fs::remove_file(&file_path).unwrap();

        assert_eq!(result, FileModeComparison::UserOrGroupPermissionsDiffers);
    }

    #[test]
    fn test_verify_file_permissions_should_return_user_or_group_permissions_differs_when_group_permission_differs(
    ) {
        let file_perm = 0o640;
        let expected_file_perm = 0o600;
        let file_path =
            create_file_with_specific_permission(file_perm, "file_640_expected_600.txt");
        let (result, _) = verify_file_permissions(&file_path, expected_file_perm).unwrap();
        std::fs::remove_file(&file_path).unwrap();
        assert_eq!(result, FileModeComparison::UserOrGroupPermissionsDiffers);
    }

    #[test]
    fn test_verify_file_permissions_should_return_an_error_when_world_permission_differs() {
        let file_perm = 0o604;
        let expected_file_perm = 0o600;
        let file_path =
            create_file_with_specific_permission(file_perm, "file_604_expected_600.txt");
        let e = verify_file_permissions(&file_path, expected_file_perm);
        std::fs::remove_file(&file_path).unwrap();

        assert_eq!(
            e,
            Err(CcError::OtherUsersFilePermissionMismatch {
                filename: file_path.display().to_string(),
                file_perm,
                default_perm: expected_file_perm,
                default_other_perm: expected_file_perm & 0o7,
            })
        );
    }

    #[test]
    pub fn test_verify_file_permissions_should_return_an_error_when_file_doesnt_exist() {
        let path = Path::new("/non/existing/path");
        let target_ugw_perm = 0o600;

        let e = verify_file_permissions(path, target_ugw_perm).unwrap_err();

        assert_eq!(e, CcError::PrivateKeyNotFound);
    }
}
