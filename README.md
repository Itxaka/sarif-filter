sarif-filter just filters a sarif file based on the given severity level. Anything below that severity level will be removed from the output file.

## Basic usage

See [action.yml](action.yml)

```yaml
steps:
- uses: itxaka/sarif-filter@v1
  with:
    input: input.sarif
    output: output.sarif
    severity: high
```

### inputs


| Name               | Type        | Description                                                                                                                                                                       |
|--------------------|-------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `input`        | string    | Input file to filter    |
| `output`            | string    | Output file to save the filtered alerts                        |
| `severity`      | string        | Max severity level to save to the file. Anything below this level will not appear in the final file                                                                                                                                           |
