WITH
    PackageInfo AS (
        SELECT
            p.id AS package_id,
            SPLIT_PART (
                p.name,
                '/',
                ARRAY_LENGTH (STRING_TO_ARRAY (p.name, '/'), 1)
            ) AS package_name,
            CASE
                WHEN p.tag LIKE '%upstream%' THEN 'Upstream'
                WHEN p.tag LIKE '%registry1%' THEN 'Registry1'
                WHEN p.tag LIKE '%unicorn%' THEN 'Unicorn'
                ELSE 'Other'
            END AS tag_category
        FROM
            packages p
        WHERE
            p.tag LIKE '%upstream%'
            OR p.tag LIKE '%registry1%'
            OR p.tag LIKE '%unicorn%'
    ),
    MaxPackageIds AS (
        SELECT
            package_name,
            tag_category,
            MAX(package_id) AS package_id
        FROM
            PackageInfo
        GROUP BY
            package_name,
            tag_category
        ORDER BY
            package_name,
            tag_category
    ),
    LatestScans AS (
        SELECT
            s.id,
            pi.package_name,
            pi.tag_category,
            MAX(DATE (s.created_at)) AS latest_scan_date
        FROM
            MaxPackageIds pi
            JOIN scans s ON pi.package_id = s.package_id
        GROUP BY
            s.id,
            pi.package_name,
            pi.tag_category
    ),
    VulnCounts AS (
        SELECT
            mpi.package_name,
            mpi.tag_category,
            COALESCE(
                COUNT(
                    CASE
                        WHEN v.severity = 'HIGH' THEN 1
                    END
                ),
                0
            ) AS high_vulnerability_count,
            COALESCE(
                COUNT(
                    CASE
                        WHEN v.severity = 'CRITICAL' THEN 1
                    END
                ),
                0
            ) AS critical_vulnerability_count
        FROM
            LatestScans mpi
            LEFT JOIN vulnerabilities v ON mpi.id = v.scan_id
            AND v.severity IN ('HIGH', 'CRITICAL')
        GROUP BY
            mpi.package_name,
            mpi.tag_category
    )
SELECT DISTINCT
    vc.package_name,
    vc.tag_category,
    mpi.latest_scan_date,
    vc.high_vulnerability_count,
    vc.critical_vulnerability_count,
    vc.high_vulnerability_count + vc.critical_vulnerability_count AS total_high_critical_vulnerability_count
FROM
    VulnCounts vc
    JOIN LatestScans mpi ON vc.package_name = mpi.package_name
    AND vc.tag_category = mpi.tag_category
ORDER BY
    vc.package_name,
    vc.tag_category;
