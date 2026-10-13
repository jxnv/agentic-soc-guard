-- ==============================================================================
-- Advanced Detection Rule: Recursive CTE for Process Tree Lineage & Ancestry
-- ATT&CK: T1059 (Execution), T1036 (Masquerading)
-- Shows deep SQL practice: Reconstructs full process tree depth for any process
-- ==============================================================================

WITH RECURSIVE ProcessTree AS (
    -- Anchor member: root / starting target process
    SELECT 
        id,
        timestamp,
        host_name,
        user_name,
        process_name,
        process_id,
        parent_process_id,
        parent_process_name,
        command_line,
        0 AS depth,
        process_name AS tree_path
    FROM endpoint_process
    WHERE process_name IN ('powershell.exe', 'cmd.exe', 'procdump64.exe')
    
    UNION ALL
    
    -- Recursive member: follow parent processes up the tree
    SELECT 
        p.id,
        p.timestamp,
        p.host_name,
        p.user_name,
        p.process_name,
        p.process_id,
        p.parent_process_id,
        p.parent_process_name,
        p.command_line,
        pt.depth + 1,
        p.process_name || ' -> ' || pt.tree_path
    FROM endpoint_process p
    JOIN ProcessTree pt ON p.process_id = pt.parent_process_id 
                        AND p.host_name = pt.host_name
    WHERE pt.depth < 5
)
SELECT 
    host_name,
    user_name,
    process_id,
    process_name,
    parent_process_name,
    command_line,
    depth,
    tree_path
FROM ProcessTree
ORDER BY host_name, depth DESC;
