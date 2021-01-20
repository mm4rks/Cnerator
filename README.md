# Cnerator


[![License](https://img.shields.io/github/license/ComputationalReflection/cnerator)](LICENSE)
[![Latest release](https://img.shields.io/github/v/release/computationalreflection/cnerator?include_prereleases)](https://github.com/ComputationalReflection/cnerator/releases)
<img alt="Code size" src="https://img.shields.io/github/languages/code-size/computationalreflection/cnerator">
<img alt="Repo size" src="https://img.shields.io/github/repo-size/computationalreflection/cnerator">



Cnerator is a C source code generation tool. It can be used to generate large amounts of 
[standard ANSI/ISO C source code](https://www.iso.org/standard/74528.html), ready to be compiled 
by any standard language implementation. 
Cnerator is highly customizable to generate all the syntactic constructs of the C language, necessary to build 
accurate predictive models with machine learning algorithms. 

## Functionalities

These are the main functionalities provided by Cnerator: 

1. _ANSI/ISO standard C_. All the source code generated by Cnerator follows the ISO/IEC 9899:2018 (C17) 
standard specification.
 
2. _Probabilistic randomness_. C language constructs are randomly generated, following different probability 
distributions specified by the user. For example, it is possible to describe the probability of each statement 
and expression construct, the number of statements in a function, and the types of their arguments and return values. 
To this aim, the user can specify fixed probabilities of each element, or use different probability distributions, 
such as normal, uniform and direct and inverse proportional. 

3. _Compilable code_. The generated code strictly follows the syntax grammar, type system and semantic 
rules of the C programming language. In this way, the generated code has been checked to be compilable 
by any standard compiler implementation. 

4. _Highly customizable_. Many features of the programs to be generated are customizable. 
Some examples include the types of each language construct, array dimensions and sizes, struct fields, 
maximum depth of expression and statement trees, number of function parameters and statements, 
global and local variables, structures of control flow statements and type promotions, 
among others –see the detailed [documentation](documentation). 

5. _Large amounts of code_. Cnerator is designed to allow generating large amounts of C source code. 
A parameter indicates the number of independent compilation units to be created for the output application, 
so that each unit could be treated as an independently compilable module. This feature, together with the 
probabilistic randomness, make Cnerator an ideal tool to create predictive models of source code, because 
the input programs used to train such models comprise abundant and varied code patterns. 

## Usage

To run Cnerator, you need to install the `singledispatch` Python package first:


``` text
pip install singledispatch
```

Then, you may just run Cnerator with no arguments to generate a random C program:


``` text
python cnerator.py
```

There are plenty of options to customize Cnerator. To specify the probability of a particular language
construct, you can use the `-p` or `--probs` option. 
The following command sets to 20% the probability of
generating a function invocation when a new expression is required:

``` text
python cnerator.py -p "call_prob = {True: 0.2, False: 0.8}"
```

If more sophisticated probabilities are required, you can specify them in a JSON file and pass it as
a parameter (see the [documentation](documentation#probability-specification-files) to know the JSON file format). 
The following line passes an example JSON file in the `json/probabilities` folder where
different probability distributions are specified for some syntactic constructs:

``` text
python cnerator.py -P json/probabilities/example_probs.json
```

Cnerator also provides allows the user to control the number and characteristics of 
all the functions to be generated. A JSON file is used for that purpose 
(see the [documentation](documentation#function-generation-files)). 
The following command makes Cnerator generate one function for each high-level return
type in the C programming language:


``` text
python cnerator.py -f json/functions/1-function-each-type.json
```

Sometimes, the user needs the output program to fulfill some requirements not guaranteed by the 
stochastic generation process.
To this aim, Cnerator allows the specification of an ordered collection of Python 
post-process specification files (see the [documentation](documentation#post-processing-specification-files)). 
These post-processing files can modify the generated code to satisfy those requirements. 
The following execution generates a random program and then executes two visitors: 
one to rename `func` functions to `proc` (and their invocations) when they return `void`;
and another one to add a `__RETURN__` label before each return statement:

``` text
python cnerator.py -V visitors.func_to_proc:visitors.return_instrumentation
```

To see all the options, just run the `-h` or `--help` options.
For more information, please check the [documentation](documentation).
Developer documentation is also provided [here](docs).


## License

[BSD 3 clause license](LICENSE)