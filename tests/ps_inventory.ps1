# Lists what a PowerShell script can do, read from its syntax tree rather than its text:
# the commands it runs, the .NET methods it calls, the types it names, the properties and
# provider paths it writes to and the files it redirects output into.
# tests/test_readonly.py checks each list against an allowlist.
# Takes one or more script paths; prints one line of JSON, an object keyed by path.
param([Parameter(Mandatory = $true, ValueFromRemainingArguments = $true)][string[]]$Path)

$ErrorActionPreference = 'Stop'

function Get-Argument($element) {
    if ($element -is [System.Management.Automation.Language.StringConstantExpressionAst]) { return $element.Value }
    if ($element -is [System.Management.Automation.Language.CommandParameterAst]) { return '-' + $element.ParameterName }
    return $element.Extent.Text
}

function Get-Inventory([string]$file) {
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$tokens, [ref]$errors)
    $commands = New-Object System.Collections.ArrayList
    $methods = New-Object System.Collections.ArrayList
    $types = New-Object System.Collections.ArrayList
    $dynamic = New-Object System.Collections.ArrayList
    $assigned = New-Object System.Collections.ArrayList
    $drives = New-Object System.Collections.ArrayList
    $redirects = New-Object System.Collections.ArrayList

    # One pass over every node of the tree.
    foreach ($node in $ast.FindAll({ $true }, $true)) {
        switch ($node.GetType().Name) {
            'CommandAst' {
                $elements = $node.CommandElements
                [void]$commands.Add([ordered]@{
                    name     = $node.GetCommandName()  # null when the name is computed at run time
                    target   = $elements[0].Extent.Text
                    operator = [string]$node.InvocationOperator
                    args     = @(for ($i = 1; $i -lt $elements.Count; $i++) { Get-Argument $elements[$i] })
                    line     = $node.Extent.StartLineNumber
                })
            }
            'InvokeMemberExpressionAst' {
                $member = $null
                if ($node.Member -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $member = $node.Member.Value }
                $type = ''
                if ($node.Static -and $node.Expression -is [System.Management.Automation.Language.TypeExpressionAst]) {
                    $type = $node.Expression.TypeName.FullName
                }
                [void]$methods.Add([ordered]@{
                    member = $member
                    static = [bool]$node.Static
                    type   = $type
                    target = $node.Expression.Extent.Text  # what the method is called on
                    args   = @(foreach ($a in $node.Arguments) { Get-Argument $a })
                    line   = $node.Extent.StartLineNumber
                })
                # A computed member name such as $obj.$name() hides what is called.
                if ($null -eq $member) { [void]$dynamic.Add($node.Extent.Text) }
            }
            'MemberExpressionAst' {
                if ($node.Member -isnot [System.Management.Automation.Language.StringConstantExpressionAst]) {
                    [void]$dynamic.Add($node.Extent.Text)
                }
            }
            { $_ -in 'TypeExpressionAst', 'TypeConstraintAst' } { [void]$types.Add($node.TypeName.FullName) }
            'AssignmentStatementAst' {
                $left = $node.Left
                while ($left -is [System.Management.Automation.Language.ConvertExpressionAst]) { $left = $left.Child }
                if ($left -is [System.Management.Automation.Language.MemberExpressionAst]) {
                    [void]$assigned.Add('member:' + $left.Extent.Text)
                } elseif ($left -is [System.Management.Automation.Language.VariableExpressionAst] -and $left.VariablePath.DriveName) {
                    [void]$assigned.Add('drive:' + $left.Extent.Text)  # ${C:\file.txt} = ... writes a file
                }
            }
            'VariableExpressionAst' {
                if ($node.VariablePath.DriveName) { [void]$drives.Add($node.VariablePath.DriveName) }
            }
            'FileRedirectionAst' { [void]$redirects.Add($node.Location.Extent.Text) }
        }
    }

    [ordered]@{
        parse_errors = @($errors | ForEach-Object { $_.Message })
        commands     = @($commands)
        methods      = @($methods)
        types        = @($types | Sort-Object -Unique)
        dynamic      = @($dynamic)
        assigned     = @($assigned)
        drives       = @($drives | Sort-Object -Unique)
        redirects    = @($redirects)
    }
}

$result = [ordered]@{}
foreach ($file in $Path) { $result[$file] = Get-Inventory $file }
$result | ConvertTo-Json -Depth 7 -Compress
