# office365urltest
Golang script to test all microsoft office 365 urls for connectivity issues

`go run office365urltest.go`

## Sample output

`
Starting connectivity tests...
-------------------------------------------------------------------

resolved:  CDG-efz.ms-acdc.office.com.
-- outlook.office.com:443 -----------------------------------------------------------------
[2021-04-29 12:11:07] 52.97.150.2:443      1     134.67ms -
[2021-04-29 12:11:08] 40.101.137.2:443     2     16.86ms -
[2021-04-29 12:11:08] 40.101.138.18:443    3     18.39ms -
[2021-04-29 12:11:09] 52.97.150.2:443      4     16.74ms -
[2021-04-29 12:11:09] 40.101.137.2:443     5     14.41ms -
[2021-04-29 12:11:09] 40.101.138.18:443    6     15.43ms -
[2021-04-29 12:11:10] 52.97.150.2:443      7     19.27ms -
[2021-04-29 12:11:10] 40.101.137.2:443     8     14.87ms -
[2021-04-29 12:11:11] 40.101.138.18:443    9     18.26ms -
[2021-04-29 12:11:11] 52.97.150.2:443      10    15.52ms -
[2021-04-29 12:11:11] 40.101.137.2:443     11    20.01ms -
[2021-04-29 12:11:12] 52.97.150.2:443      12    18.66ms -
[2021-04-29 12:11:12] 40.101.137.2:443     13    17.03ms -
[2021-04-29 12:11:13] 52.97.150.2:443      14    16.44ms -
[2021-04-29 12:11:13] 40.101.137.2:443     15    15.28ms -
[2021-04-29 12:11:13] 40.101.138.18:443    16    15.84ms -
[2021-04-29 12:11:14] 52.97.150.2:443      17    14.91ms -
[2021-04-29 12:11:14] 40.101.137.2:443     18    14.49ms -
[2021-04-29 12:11:15] 40.101.137.34:443    19    33.85ms -
[2021-04-29 12:11:15] 52.97.150.2:443      20    19.05ms -

resolved:  outlook.ha.office365.com.
-- outlook.office365.com:443 -----------------------------------------------------------------
[2021-04-29 12:11:15] 52.97.233.66:443     1     17.69ms -
[2021-04-29 12:11:16] 52.97.150.2:443      2     18.99ms -
....
`
