# PeDumper
Used for parsing a portable executable. It will parse entirely the export and import directory, printing the names of each imported or 
exported function and its characteristics. The dumping is realised without using any auxiliary library(like loading the dll with LoadLibrary
or anything else). The executable is mapped in the virtual memory. It works on dll/exe on 32bits. Can be verified with tools like CFF Explorer.
