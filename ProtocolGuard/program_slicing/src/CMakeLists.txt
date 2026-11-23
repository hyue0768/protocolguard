# Independent pass entry points share a paper-guided implementation.
foreach(pass AnalyzerPass MatchPass AssertPass)
  add_llvm_pass_plugin(${pass} Passes.cpp)
endforeach()
