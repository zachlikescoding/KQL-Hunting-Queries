# See all tables that currently have data in ADX

## Note
Specific to Navy environment, may not apply elsewhere

## MDE
```KQL
// How to see all tables that currently have data in ADX
union withsource=SourceTable * 
| summarize RecordCount = count() by SourceTable 
| order by RecordCount asc
```
