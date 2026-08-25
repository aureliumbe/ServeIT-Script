function New-SVTestResult($testitem, $testValue, $testResultaat) {
    [pscustomobject]@{
        testItem = $testitem
        testValue = $testValue
        testResultaat = [bool]$testResultaat
    }
}

function New-SVTest($testname, [array]$arrtestresult) {
    [pscustomobject]@{
        testName = $testname
        testResult = @($arrtestresult)
    }
}

function Write-SVVerbose($text) { }
